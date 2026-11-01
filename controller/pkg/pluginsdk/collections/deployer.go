package collections

import (
	"cmp"
	"fmt"

	"istio.io/istio/pilot/pkg/serviceregistry/ambient"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/sets"
	"istio.io/istio/pkg/util/smallset"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/api/annotations"
	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/utils/kubeutils"
	"github.com/agentgateway/agentgateway/controller/pkg/wellknown"
)

type TargetRefIndexKey struct {
	Group       string
	Kind        string
	Name        string
	Namespace   string
	SectionName string
}

func (k TargetRefIndexKey) String() string {
	return fmt.Sprintf("%s/%s/%s/%s/%s", k.Group, k.Kind, k.Name, k.Namespace, k.SectionName)
}

func GatewaysForDeployerTransformationFunc(
	gatewayClasses krt.Collection[*gwv1.GatewayClass],
	listenerSets krt.Collection[*gwv1.ListenerSet],
	byParentRefIndex krt.Index[TargetRefIndexKey, *gwv1.ListenerSet],
	policies krt.Collection[*agentgateway.AgentgatewayPolicy],
	policiesByNamespace krt.Index[string, *agentgateway.AgentgatewayPolicy],
	meshConfig krt.Singleton[ambient.MeshConfig],
	controllerName string,
) func(kctx krt.HandlerContext, gw *gwv1.Gateway) *GatewayForDeployer {
	return func(kctx krt.HandlerContext, gw *gwv1.Gateway) *GatewayForDeployer {
		// only care about gateways use a class controlled by us (envoy or agentgateway)
		gwClass := ptr.Flatten(krt.FetchOne(kctx, gatewayClasses, krt.FilterKey(string(gw.Spec.GatewayClassName))))
		if gwClass == nil || controllerName != string(gwClass.Spec.ControllerName) {
			return nil
		}
		ports := sets.New[int32]()
		for _, l := range gw.Spec.Listeners {
			ports.Insert(l.Port)
		}

		// Track spec and internal-port changes through generation and the annotation.
		lsets := krt.PartialFetch(kctx, listenerSets, func(ls *gwv1.ListenerSet) *gwv1.ListenerSet {
			return ls
		}, func(a, b *gwv1.ListenerSet) bool {
			return a.Name == b.Name && a.Namespace == b.Namespace && a.UID == b.UID &&
				a.Generation == b.Generation && a.CreationTimestamp.Equal(&b.CreationTimestamp) &&
				a.Annotations[annotations.InternalPorts] == b.Annotations[annotations.InternalPorts]
		}, krt.FilterIndex(byParentRefIndex, TargetRefIndexKey{
			Group:     wellknown.GatewayGroup,
			Kind:      wellknown.GatewayKind,
			Name:      gw.GetName(),
			Namespace: gw.GetNamespace(),
		}))

		for _, ls := range lsets {
			for _, l := range ls.Spec.Listeners {
				port, portErr := kubeutils.DetectListenerPortNumber(l.Protocol, l.Port)
				// Don't need to log an error for the deployer as it will be reflected in the listener status during reconciliation
				if portErr != nil {
					continue
				}
				ports.Insert(port)
			}
		}

		// Only policies enabling HTTP/3 change the deployment, so only they are tracked.
		http3Policies := krt.Fetch(kctx, policies, krt.FilterIndex(policiesByNamespace, gw.Namespace), krt.FilterGeneric(func(o any) bool {
			return EnablesHTTP3(o.(*agentgateway.AgentgatewayPolicy))
		}))

		td := ptr.OrEmpty(slices.First(krt.PartialFetchComparable(kctx, meshConfig.AsCollection(), func(mc ambient.MeshConfig) string {
			return mc.TrustDomain
		})))

		ir := &GatewayForDeployer{
			Group:           gwv1.GroupVersion.Group,
			Kind:            wellknown.GatewayKind,
			Namespace:       gw.Namespace,
			Name:            gw.Name,
			ControllerName:  string(gwClass.Spec.ControllerName),
			Ports:           smallset.New(ports.UnsortedList()...),
			InternalPorts:   ComputeInternalPorts(gw, lsets),
			HTTP3Ports:      ComputeHTTP3Ports(gw, lsets, http3Policies),
			MeshTrustDomain: td,
		}
		return ir
	}
}

// ComputeInternalPorts returns the ports whose winning listener selects an internal
// bind. Gateway listeners have precedence over ListenerSets. ListenerSets are ordered
// oldest first, then by namespace/name, matching listener conflict validation.
// A lower-precedence listener with a different mode is rejected by translation and
// cannot change Service/container exposure here.
func ComputeInternalPorts(gw *gwv1.Gateway, lsets []*gwv1.ListenerSet) smallset.Set[int32] {
	if gw.GetAnnotations()[annotations.InternalPorts] == "" {
		// Fastpath: no internal ports. Avoids expensive sort of the LS collection
		hasInternalPorts := false
		for _, ls := range lsets {
			if ls.GetAnnotations()[annotations.InternalPorts] != "" {
				hasInternalPorts = true
				break
			}
		}
		if !hasInternalPorts {
			return smallset.New[int32]()
		}
	}
	portModes := map[int32]bool{}

	gwInternal, _ := annotations.ParseInternalPorts(
		gw.GetAnnotations()[annotations.InternalPorts],
		func(p int32) bool {
			for _, l := range gw.Spec.Listeners {
				if l.Port == p {
					return true
				}
			}
			return false
		},
	)
	for _, l := range gw.Spec.Listeners {
		portModes[l.Port] = gwInternal.Has(l.Port)
	}

	slices.SortFunc(lsets, func(a, b *gwv1.ListenerSet) int {
		if r := a.CreationTimestamp.Compare(b.CreationTimestamp.Time); r != 0 {
			return r
		}
		if r := cmp.Compare(a.Namespace, b.Namespace); r != 0 {
			return r
		}
		return cmp.Compare(a.Name, b.Name)
	})
	for _, ls := range lsets {
		lsInternal, _ := annotations.ParseInternalPorts(
			ls.GetAnnotations()[annotations.InternalPorts],
			func(p int32) bool {
				for _, l := range ls.Spec.Listeners {
					if port, err := kubeutils.DetectListenerPortNumber(l.Protocol, l.Port); err == nil && port == p {
						return true
					}
				}
				return false
			},
		)
		for _, l := range ls.Spec.Listeners {
			port, err := kubeutils.DetectListenerPortNumber(l.Protocol, l.Port)
			if err != nil {
				continue
			}
			if _, winnerSelected := portModes[port]; !winnerSelected {
				portModes[port] = lsInternal.Has(port)
			}
		}
	}

	internal := sets.New[int32]()
	for port, mode := range portModes {
		if mode {
			internal.Insert(port)
		}
	}
	return smallset.New(internal.UnsortedList()...)
}

type GatewayForDeployer struct {
	ObjectSource
	// Controller name for the gateway
	ControllerName string
	// All ports from all listeners
	Ports smallset.Set[int32]
	// InternalPorts are ports whose bind is internal (routing-only). They are excluded
	// from the generated Service and container ports. Derived from the winning listener's
	// agentgateway.dev/internal-ports annotation.
	InternalPorts smallset.Set[int32]
	// HTTP3Ports are HTTPS listener ports on which an AgentgatewayPolicy enables HTTP/3.
	// Their UDP port is exposed on the generated Service as well.
	HTTP3Ports smallset.Set[int32]
	// MeshTrustDomain changes should trigger reconciliation
	// this field isn't read outside of Equals for a trigger
	MeshTrustDomain string
}

type ObjectSource struct {
	Group     string `json:"group,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// GetKind returns the kind of the route.
func (c ObjectSource) GetGroupKind() schema.GroupKind {
	return schema.GroupKind{
		Group: c.Group,
		Kind:  c.Kind,
	}
}

// GetName returns the name of the route.
func (c ObjectSource) GetName() string {
	return c.Name
}

// GetNamespace returns the namespace of the route.
func (c ObjectSource) GetNamespace() string {
	return c.Namespace
}

// EnablesHTTP3 reports whether the policy enables HTTP/3 on the Gateways it targets.
func EnablesHTTP3(policy *agentgateway.AgentgatewayPolicy) bool {
	return policy.Spec.Frontend != nil && policy.Spec.Frontend.HTTP != nil && policy.Spec.Frontend.HTTP.HTTP3 != nil
}

// ComputeHTTP3Ports returns the HTTPS listener ports of the Gateway, including those of its
// ListenerSets, on which one of the policies enables HTTP/3: the ports a policy targets, or every
// HTTPS listener port when it targets the whole Gateway. The data plane serves HTTP/3 on the UDP
// port with the same number. Policy precedence is not resolved here: exposing a UDP port that ends
// up unused is harmless, since HTTP/3 is only advertised while it is served.
func ComputeHTTP3Ports(gw *gwv1.Gateway, lsets []*gwv1.ListenerSet, policies []*agentgateway.AgentgatewayPolicy) smallset.Set[int32] {
	if len(policies) == 0 {
		return smallset.New[int32]()
	}
	httpsPorts := sets.New[int32]()
	for _, l := range gw.Spec.Listeners {
		if l.Protocol == gwv1.HTTPSProtocolType {
			httpsPorts.Insert(l.Port)
		}
	}
	for _, ls := range lsets {
		for _, l := range ls.Spec.Listeners {
			if l.Protocol != gwv1.HTTPSProtocolType {
				continue
			}
			if port, err := kubeutils.DetectListenerPortNumber(l.Protocol, l.Port); err == nil {
				httpsPorts.Insert(port)
			}
		}
	}
	ports := sets.New[int32]()
	enable := func(port *int32) {
		if port == nil {
			ports.InsertAll(httpsPorts.UnsortedList()...)
		} else if httpsPorts.Contains(*port) {
			ports.Insert(*port)
		}
	}
	isGateway := func(group gwv1.Group, kind gwv1.Kind) bool {
		return string(group) == wellknown.GatewayGroup && string(kind) == wellknown.GatewayKind
	}
	for _, policy := range policies {
		if policy.Namespace != gw.Namespace || !EnablesHTTP3(policy) {
			continue
		}
		for _, ref := range policy.Spec.TargetRefs {
			if isGateway(ref.Group, ref.Kind) && string(ref.Name) == gw.Name {
				enable(ref.Port)
			}
		}
		for _, selector := range policy.Spec.TargetSelectors {
			if isGateway(selector.Group, selector.Kind) &&
				labels.SelectorFromSet(selector.MatchLabels).Matches(labels.Set(gw.Labels)) {
				enable(selector.Port)
			}
		}
	}
	return smallset.New(ports.UnsortedList()...)
}

func (c ObjectSource) ResourceName() string {
	return fmt.Sprintf("%s/%s/%s/%s", c.Group, c.Kind, c.Namespace, c.Name)
}

func (c ObjectSource) String() string {
	return fmt.Sprintf("%s/%s/%s/%s", c.Group, c.Kind, c.Namespace, c.Name)
}

func (c ObjectSource) Equals(in ObjectSource) bool {
	return c.Namespace == in.Namespace && c.Name == in.Name && c.Group == in.Group && c.Kind == in.Kind
}

func (c ObjectSource) NamespacedName() types.NamespacedName {
	return types.NamespacedName{
		Namespace: c.Namespace,
		Name:      c.Name,
	}
}
func (c GatewayForDeployer) ResourceName() string {
	return c.ObjectSource.ResourceName()
}

func (c GatewayForDeployer) Equals(in GatewayForDeployer) bool {
	return c.ObjectSource.Equals(in.ObjectSource) &&
		c.ControllerName == in.ControllerName &&
		c.MeshTrustDomain == in.MeshTrustDomain &&
		slices.Equal(c.Ports.List(), in.Ports.List()) &&
		slices.Equal(c.InternalPorts.List(), in.InternalPorts.List()) &&
		slices.Equal(c.HTTP3Ports.List(), in.HTTP3Ports.List())
}

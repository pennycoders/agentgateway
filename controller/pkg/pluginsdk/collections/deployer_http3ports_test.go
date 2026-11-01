package collections

import (
	"testing"
	"time"

	"istio.io/istio/pilot/pkg/serviceregistry/ambient"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
)

func http3Gateway(labels map[string]string, listeners ...gwv1.Listener) *gwv1.Gateway {
	g := &gwv1.Gateway{
		Name: "gw", Namespace: "ns", Labels: labels,
	}
	g.Spec.Listeners = listeners
	return g
}

func listener(name string, protocol gwv1.ProtocolType, port gwv1.PortNumber) gwv1.Listener {
	return gwv1.Listener{Name: gwv1.SectionName(name), Protocol: protocol, Port: port}
}

func http3Policy(namespace string, refs []agentgateway.LocalPolicyTargetReferenceWithSectionName, selectors []agentgateway.LocalPolicyTargetSelectorWithSectionName) *agentgateway.AgentgatewayPolicy {
	return &agentgateway.AgentgatewayPolicy{
		Name: "p", Namespace: namespace,
		Spec: agentgateway.AgentgatewayPolicySpec{
			TargetRefs:      refs,
			TargetSelectors: selectors,
			Frontend: &agentgateway.Frontend{
				HTTP: &agentgateway.FrontendHTTP{HTTP3: &agentgateway.FrontendHTTP3{}},
			},
		},
	}
}

func gatewayRef(name string, port *int32) []agentgateway.LocalPolicyTargetReferenceWithSectionName {
	return []agentgateway.LocalPolicyTargetReferenceWithSectionName{{
		Group: gwv1.GroupName,
		Kind:  "Gateway",
		Name:  gwv1.ObjectName(name),
		Port:  port,
	}}
}

func TestComputeHTTP3Ports(t *testing.T) {
	port := func(p int32) *int32 { return &p }
	gateway := http3Gateway(map[string]string{"app": "edge"},
		listener("http", gwv1.HTTPProtocolType, 80),
		listener("https", gwv1.HTTPSProtocolType, 443),
		listener("alt", gwv1.HTTPSProtocolType, 8443),
		listener("passthrough", gwv1.TLSProtocolType, 9443),
	)
	listenerSet := &gwv1.ListenerSet{Name: "ls", Namespace: "ns", CreationTimestamp: metav1.NewTime(time.Now())}
	listenerSet.Spec.Listeners = []gwv1.ListenerEntry{{Name: "extra", Protocol: gwv1.HTTPSProtocolType, Port: 10443}}

	noHTTP3 := http3Policy("ns", gatewayRef("gw", nil), nil)
	noHTTP3.Spec.Frontend.HTTP.HTTP3 = nil

	tests := []struct {
		name     string
		lsets    []*gwv1.ListenerSet
		policies []*agentgateway.AgentgatewayPolicy
		want     []int32
	}{
		{
			name: "no policy",
			want: nil,
		},
		{
			name:     "gateway target enables every HTTPS listener port",
			lsets:    []*gwv1.ListenerSet{listenerSet},
			policies: []*agentgateway.AgentgatewayPolicy{http3Policy("ns", gatewayRef("gw", nil), nil)},
			want:     []int32{443, 8443, 10443},
		},
		{
			name:     "port target enables only that port",
			policies: []*agentgateway.AgentgatewayPolicy{http3Policy("ns", gatewayRef("gw", port(8443)), nil)},
			want:     []int32{8443},
		},
		{
			name:     "ports without an HTTPS listener are not exposed",
			policies: []*agentgateway.AgentgatewayPolicy{http3Policy("ns", gatewayRef("gw", port(80)), nil)},
			want:     nil,
		},
		{
			name:     "other gateways and namespaces are ignored",
			policies: []*agentgateway.AgentgatewayPolicy{http3Policy("ns", gatewayRef("other", nil), nil), http3Policy("other", gatewayRef("gw", nil), nil)},
			want:     nil,
		},
		{
			name:     "policies without http3 are ignored",
			policies: []*agentgateway.AgentgatewayPolicy{noHTTP3},
			want:     nil,
		},
		{
			name: "label selectors",
			policies: []*agentgateway.AgentgatewayPolicy{
				http3Policy("ns", nil, []agentgateway.LocalPolicyTargetSelectorWithSectionName{{
					Group: gwv1.GroupName, Kind: "Gateway", MatchLabels: map[string]string{"app": "edge"},
					Port: port(443),
				}}),
				http3Policy("ns", nil, []agentgateway.LocalPolicyTargetSelectorWithSectionName{{
					Group: gwv1.GroupName, Kind: "Gateway", MatchLabels: map[string]string{"app": "other"},
				}}),
			},
			want: []int32{443},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeHTTP3Ports(gateway, tt.lsets, tt.policies).List()
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGatewaysForDeployerTracksHTTP3Policies(t *testing.T) {
	stop := test.NewStop(t)
	opts := []krt.CollectionOption{krt.WithStop(stop)}
	classes := krt.NewStaticCollection(nil, []*gwv1.GatewayClass{{
		Name: "agw",
		Spec: gwv1.GatewayClassSpec{ControllerName: "example.com/agw"},
	}}, opts...)
	gateway := http3Gateway(nil, listener("https", gwv1.HTTPSProtocolType, 443))
	gateway.Spec.GatewayClassName = "agw"
	gateways := krt.NewStaticCollection(nil, []*gwv1.Gateway{gateway}, opts...)
	listenerSets := krt.NewStaticCollection[*gwv1.ListenerSet](nil, nil, opts...)
	byParentRef := krt.NewIndex(listenerSets, "parent", func(*gwv1.ListenerSet) []TargetRefIndexKey { return nil })
	policies := krt.NewMutableCollection[*agentgateway.AgentgatewayPolicy](nil, nil, opts...)
	byNamespace := krt.NewNamespaceIndex(policies.AsCollection())
	meshConfig := krt.NewStatic(&ambient.MeshConfig{MeshConfig: mesh.DefaultMeshConfig()}, true, opts...)
	deployed := krt.NewCollection(gateways, GatewaysForDeployerTransformationFunc(
		classes, listenerSets, byParentRef, policies.AsCollection(), byNamespace, meshConfig, "example.com/agw",
	), opts...)
	deployed.WaitUntilSynced(stop)

	http3Ports := func() []int32 {
		gw := deployed.GetKey(gwv1.GroupName + "/Gateway/ns/gw")
		if gw == nil {
			return []int32{-1}
		}
		return gw.HTTP3Ports.List()
	}
	assert.EventuallyEqual(t, http3Ports, []int32{})

	// Enabling HTTP/3 exposes the UDP port; disabling it removes it again.
	policies.UpdateObject(http3Policy("ns", gatewayRef("gw", nil), nil))
	assert.EventuallyEqual(t, http3Ports, []int32{443})
	policies.DeleteObject("ns/p")
	assert.EventuallyEqual(t, http3Ports, []int32{})
}

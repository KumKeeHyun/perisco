package maps

import (
	"testing"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
)

func TestProtocolMap_Detect(t *testing.T) {
	type args struct {
		proto types.ProtocolType
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Detect HTTP1",
			args: args{
				proto: types.HTTP1,
			},
			wantErr: false,
		},{
			name: "Detect HTTP2",
			args: args{
				proto: types.HTTP2,
			},
			wantErr: false,
		},
		{
			name: "Detect UNKNOWN",
			args: args{
				proto: types.PROTO_UNKNOWN,
			},
			wantErr: true,
		},
		{
			name: "Detect SKIP",
			args: args{
				proto: types.PROTO_SKIP,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &ProtocolMap{
				m: &MockMap{},
			}
			if err := pm.Detect(types.EndpointKey{}, tt.args.proto); (err != nil) != tt.wantErr {
				t.Errorf("ProtocolMap.Detect() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

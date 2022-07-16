package protocols

import (
	"testing"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/maps"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
)

func Test_protoDetecter_Success(t *testing.T) {
	mockPm := maps.NewProtocolMap(&maps.MockMap{})

	tests := []struct {
		name    string
		sockKey types.SockKey
		args    []types.ProtocolType
		want    types.ProtocolType
	}{
		{
			name: "HTTP1",
			sockKey: types.SockKey{},
			args: []types.ProtocolType{
				types.HTTP1,
				types.HTTP1,
			},
			want: types.HTTP1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pd := NewProtoDetecter(mockPm)
			for _, arg := range tt.args {
				pd.Success(tt.sockKey, arg)
			}
			if pt, exists := pd.detected[tt.sockKey.ToEndpointKey()]; !exists || pt != tt.want {
				t.Errorf("protoDetecter.detected[ek] = %v, want = %v", pt, tt.want)
			}
		})
	}
}

func Test_protoDetecter_Fail(t *testing.T) {
	mockPm := maps.NewProtocolMap(&maps.MockMap{})

	type args struct {
		sockKey types.SockKey
	}
	tests := []struct {
		name    string
		sockKey types.SockKey
		exec func(pd *protoDetecter, sk types.SockKey)
		wantSkip bool
	}{
		{
			name: "fail more than failureThreshold",
			sockKey: types.SockKey{},
			exec: func(pd *protoDetecter, sk types.SockKey) {
				for i := 0; i < failureThreshold; i++ {
					pd.Fail(sk)
				}
			},
			wantSkip: true,
		},
		{
			name: "fail 5 times, success, fail more than failureThreshold",
			sockKey: types.SockKey{},
			exec: func(pd *protoDetecter, sk types.SockKey) {
				for i := 0; i < 5; i++ {
					pd.Fail(sk)
				}
				pd.Success(sk, types.HTTP1)
				for i := 0; i < failureThreshold; i++ {
					pd.Fail(sk)
				}
			},
			wantSkip: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pd := NewProtoDetecter(mockPm)
			tt.exec(pd, tt.sockKey)
			skipped := pd.alreadySkipped(tt.sockKey.ToEndpointKey())
			if skipped != tt.wantSkip {
				t.Errorf("got = %v, want = %v", skipped, tt.wantSkip)
			}
		})
	}
}

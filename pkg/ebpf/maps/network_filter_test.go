package maps

import "testing"

func TestNetworkFilter_RegisterCIDRs(t *testing.T) {
	type args struct {
		cidrs []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "IPv4 cidrs",
			args: args{
				cidrs: []string{
					"0.0.0.0/0",
					"192.168.0.1/16",
					"1.2.3.4/24",
					"1.1.1.1/32",
				},
			},
			wantErr: false,
		},
		{
			name: "IPv6 cidrs",
			args: args{
				cidrs: []string{
					"::FFFF:C0A8:1/0",
					"::FFFF:C0A8:0001/32",
					"::FFFF:192.168.0.1/96",
				},
			},
			wantErr: false,
		},
		{
			name: "Too much cidrs",
			args: args{
				cidrs: []string{
					"0.0.0.0/0",
					"0.0.0.0/0",
					"0.0.0.0/0",
					"0.0.0.0/0",
					"0.0.0.0/0",
					"0.0.0.0/0",
				},
			},
			wantErr: true,
		},
		{
			name: "Illegal cidrs",
			args: args{
				cidrs: []string{
					"a.b.c.d/e",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nf := &NetworkFilter{
				m: &MockMap{},
			}
			if err := nf.RegisterCIDRs(tt.args.cidrs); (err != nil) != tt.wantErr {
				t.Errorf("NetworkFilter.RegisterCIDRs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

package run

import (
	"context"
	"log"
	"os/signal"
	"strings"
	"syscall"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
	"github.com/KumKeeHyun/perisco/pkg/protocols"
	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	keyCidrs = "cidrs"
)

func New(vp *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "run perisco",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runPerisco(vp)
		},
	}

	flags := cmd.Flags()
	flags.String(keyCidrs, "0.0.0.0/0", "List of cidr to monitor sevices")
	vp.BindPFlags(flags)

	return cmd
}

func runPerisco(vp *viper.Viper) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer cancel()

	recvc, sendc, nf, pm, clean := bpf.LoadBpfProgram()
	defer clean()

	cidrs := splitCidrs(vp.GetString(keyCidrs))
	if err := nf.RegisterCIDRs(cidrs); err != nil {
		log.Fatal(err)
	}
	log.Printf("cidrs : %v", cidrs)

	pd := protocols.NewProtoDetecter(pm)
	reqc, respc := protocols.RunParser(ctx, recvc, sendc, pd)
	msgc := protocols.RunMatcher(ctx, reqc, respc)

	return func() error {
		for {
			select {
			case msg := <-msgc:
				log.Println(msg)
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}()
}

func splitCidrs(cidrs string) []string {
	return strings.Split(strings.ReplaceAll(cidrs, " ", ""), ",")
}

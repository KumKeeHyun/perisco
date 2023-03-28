package start

import (
	"context"
	"os/signal"
	"strings"
	"syscall"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/exporters/stdout"
	"github.com/KumKeeHyun/perisco/pkg/logger"
	"github.com/KumKeeHyun/perisco/pkg/perisco"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	keyCidrs  = "cidrs"
	keyProtos = "protos"
)

func New(vp *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "start perisco node agent",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runPerisco(vp)
		},
	}

	flags := cmd.Flags()
	flags.String(keyCidrs, "0.0.0.0/0", "List of cidr to monitor sevices")
	flags.String(keyProtos, "HTTP/1,HTTP/2", "List of protocols to monitor services")
	vp.BindPFlags(flags)

	return cmd
}

func runPerisco(vp *viper.Viper) error {
	log := logger.DefualtLogger.Named("perisco")

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer cancel()

	protos, err := types.ProtoTypesOf(splitToSlice(vp.GetString(keyProtos)))
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("enabled protocols %v", protos)

	recvc, sendc, nf, pm, clean := bpf.LoadBpfProgram()
	defer clean()

	cidrs := splitToSlice(vp.GetString(keyCidrs))
	if err := nf.RegisterCIDRs(cidrs); err != nil {
		log.Fatal(err)
	}
	log.Infof("network filter will only tract %v", cidrs)

	breaker := perisco.NewProtoDetecter(pm, log.Named("breaker"))
	parser, err := perisco.NewParser(
		perisco.ParserWithProtocols(protos),
		perisco.ParserWithBreaker(breaker),
		perisco.ParserWithLogger(log.Named("parser")),
	)
	if err != nil {
		log.Fatal(err)
	}
	reqc, respc := parser.Run(ctx, recvc, sendc)

	matcher, err := perisco.NewMatcher(
		perisco.MatcherWithProtocols(protos),
		perisco.MatcherWithLogger(log.Named("matcher")),
	)
	if err != nil {
		log.Fatal(err)
	}
	msgc := matcher.Run(ctx, reqc, respc)

	// exporter, _ := stdout.New(stdout.WithPretty())
	exporter, _ := stdout.New()
	go exporter.Export(ctx, msgc)

	return func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}()
}

func splitToSlice(str string) []string {
	return strings.Split(strings.ReplaceAll(str, " ", ""), ",")
}

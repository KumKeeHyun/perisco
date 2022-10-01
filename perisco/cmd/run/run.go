package run

import (
	"context"
	"os/signal"
	"strings"
	"syscall"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/exporters/stdout"
	"github.com/KumKeeHyun/perisco/pkg/logger"
	"github.com/KumKeeHyun/perisco/pkg/protocols"
	"github.com/KumKeeHyun/perisco/pkg/protocols/http1"
	"github.com/KumKeeHyun/perisco/pkg/protocols/http2"
	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	keyCidrs  = "cidrs"
	keyProtos = "protos"
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
	flags.String(keyProtos, "HTTP/1,HTTP/2", "List of protocols to monitor services")
	vp.BindPFlags(flags)

	return cmd
}

func runPerisco(vp *viper.Viper) error {
	log := logger.DefualtLogger.Named("perisco")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

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

	breaker := protocols.NewProtoDetecter(pm, log.Named("breaker"))
	parser := protocols.NewParser(
		supportedProtoParsers(protos),
		breaker,
		log.Named("parser"),
	)
	reqc, respc := parser.Run(ctx, recvc, sendc)

	matcher := protocols.NewMatcher(
		supportedProtoMatchers(protos),
		log.Named("matcher"),
	)
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

func supportedProtoParsers(protos []types.ProtocolType) (parsers []protocols.ProtoParser) {
	for _, proto := range protos {
		if proto != types.PROTO_UNKNOWN {
			parsers = append(parsers, protoParserOf(proto))
		}

	}
	return
}

func protoParserOf(pt types.ProtocolType) protocols.ProtoParser {
	switch pt {
	case types.HTTP1:
		return http1.NewHTTP1Parser()
	case types.HTTP2:
		return http2.NewHTTP2Parser()
	default:
		return nil
	}
}

func supportedProtoMatchers(protos []types.ProtocolType) func(types.ProtocolType) protocols.ProtoMatcher {
	support := make(map[types.ProtocolType]struct{})
	for _, proto := range protos {
		if proto != types.PROTO_UNKNOWN {
			support[proto] = struct{}{}
		}
	}

	return func(pt types.ProtocolType) protocols.ProtoMatcher {
		if _, exists := support[pt]; exists {
			return protoMatcherOf(pt)
		}
		return nil
	}
}

func protoMatcherOf(pt types.ProtocolType) protocols.ProtoMatcher {
	switch pt {
	case types.HTTP1:
		return http1.NewHTTP1Matcher()
	case types.HTTP2:
		return http2.NewHTTP2Matcher()
	default:
		return nil
	}
}

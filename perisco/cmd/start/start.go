package start

import (
	"context"
	"os/signal"
	"strings"
	"syscall"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
	"github.com/KumKeeHyun/perisco/perisco/server"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/exporter"
	"github.com/KumKeeHyun/perisco/pkg/kubernetes"
	"github.com/KumKeeHyun/perisco/pkg/logger"
	"github.com/KumKeeHyun/perisco/pkg/perisco"
	"github.com/cilium/ebpf/rlimit"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
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
	setFlags(flags)
	vp.BindPFlags(flags)

	return cmd
}

func runPerisco(vp *viper.Viper) error {
	log := logger.DefualtLogger.Named("perisco")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("failed to remove mem lock", "err", err)
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer cancel()

	var clientset *k8s.Clientset
	if vp.GetBool(keyKubernetes) {
		masterUrl, kubeconfigPath := vp.GetString(keyKubernetesMasterUrl), vp.GetString(keyKubernetesConfigPath)
		log.Infow("build k8s config", "masterUrl", masterUrl, "kubeconfigPath", kubeconfigPath)

		config, err := clientcmd.BuildConfigFromFlags(masterUrl, kubeconfigPath)
		if err != nil {
			log.Fatalw("failed to build k8s config", "err", err)
		}
		clientset, err = k8s.NewForConfig(config)
		if err != nil {
			log.Fatalw("failed to create k8s clientset", "err", err)
		}
		log.Info("success to create k8s clientset")
	}

	recvc, sendc, nf, pm, cleanUpBPF := bpf.LoadBpfProgram()
	defer cleanUpBPF()
	log.Info("success to load bpf program")

	cidrs := splitToSlice(vp.GetString(keyCidrs))
	if err := nf.RegisterCIDRs(cidrs); err != nil {
		log.Fatal(err)
	}
	log.Infow("trace cidr", "cidrs", cidrs)

	protosCfg := vp.GetString(keyProtos)
	protos, err := types.ProtoTypesOf(splitToSlice(protosCfg))
	if err != nil {
		log.Fatal(err)
	}
	log.Infow("trace protocol", "protocols", lo.Map[types.ProtocolType, string](protos, func(item types.ProtocolType, index int) string { return item.String() }))

	breaker := perisco.NewProtoDetecter(pm, log.Named("breaker"))
	parser, err := perisco.NewParser(
		perisco.ParserWithProtocols(protos),
		perisco.ParserWithBreaker(breaker),
		perisco.ParserWithLogger(log.Named("parser")),
	)
	if err != nil {
		log.Fatalw("failed to create parser", "err", err)
	}
	reqc, respc := parser.Run(ctx, recvc, sendc)
	defer parser.Stop()

	matcher, err := perisco.NewMatcher(
		perisco.MatcherWithProtocols(protos),
		perisco.MatcherWithLogger(log.Named("matcher")),
	)
	if err != nil {
		log.Fatalw("failed to create matcher", "err", err)
	}
	msgc := matcher.Run(ctx, reqc, respc)
	defer matcher.Stop()

	var exporterCfg exporter.Config
	if err = vp.Unmarshal(&exporterCfg); err != nil {
		log.Fatalw("failed to unmarshal exporter config", "err", err)
	}
	exporter, err := exporter.New(exporterCfg)
	if err != nil {
		log.Fatalw("failed to create exporter", "err", err)
	}
	defer exporter.Stop()

	if vp.GetBool(keyKubernetes) {
		s := kubernetes.NewStore()
		watcher := kubernetes.NewWatcher(log.Named("watcher"), clientset.CoreV1(), s)
		if err := watcher.WatchEvents(ctx); err != nil {
			log.Fatalw("failed to create k8s watcher", "err", err)
		}
		defer watcher.Stop()

		enricher, err := perisco.NewEnricher(log.Named("enricher"), s)
		if err != nil {
			log.Fatalw("failed to create enricher", "err", err)
		}

		k8sMsgs := enricher.Run(ctx, msgc)
		defer enricher.Stop()

		go exporter.ExportK8S(ctx, k8sMsgs)
	} else {
		go exporter.Export(ctx, msgc)
	}

	go func() {
		log.Fatalw("failed to run server", "err", server.RunServer(log.Named("server"), vp.GetBool(keyServerDebugHandler), vp.GetInt(keyServerPort)))
	}()

	<-ctx.Done()
	return nil
}

func splitToSlice(str string) []string {
	return strings.Split(strings.ReplaceAll(str, " ", ""), ",")
}

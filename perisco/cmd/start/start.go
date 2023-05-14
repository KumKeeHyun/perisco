package start

import (
	"context"
	"os/signal"
	"strings"
	"syscall"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/exporter"
	"github.com/KumKeeHyun/perisco/pkg/exporter/file"
	"github.com/KumKeeHyun/perisco/pkg/kubernetes"
	"github.com/KumKeeHyun/perisco/pkg/logger"
	"github.com/KumKeeHyun/perisco/pkg/perisco"
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

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer cancel()

	var clientset *k8s.Clientset
	if vp.GetBool(keyKubernetes) {
		masterUrl, kubeconfigPath := vp.GetString(keyKubernetesMasterUrl), vp.GetString(keyKubernetesConfigPath)
		log.Infof("try to create k8s client with masterUrl(%s), kubeconfigPath(%s)", masterUrl, kubeconfigPath)

		config, err := clientcmd.BuildConfigFromFlags(masterUrl, kubeconfigPath)
		if err != nil {
			log.Fatalf("failed to build k8s client config: %w", err)
		}
		clientset, err = k8s.NewForConfig(config)
		if err != nil {
			log.Fatal(err)
		}
		log.Info("created k8s client successfully")
	}

	log.Info("loading bpf program")
	recvc, sendc, nf, pm, clean := bpf.LoadBpfProgram()
	defer clean()

	cidrs := splitToSlice(vp.GetString(keyCidrs))
	if err := nf.RegisterCIDRs(cidrs); err != nil {
		log.Fatal(err)
	}
	log.Infof("set cidrs to trace sockets %v", cidrs)

	protos, err := types.ProtoTypesOf(splitToSlice(vp.GetString(keyProtos)))
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("set protocols to parse payload to %v", protos)

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

	var exporterCfg exporter.Config
	if err = vp.Unmarshal(&exporterCfg); err != nil {
		log.Fatal(err)
	}
	exporter, err := file.New(exporterCfg.FileConfig)
	if err != nil {
		log.Fatal(err)
	}

	if vp.GetBool(keyKubernetes) {
		s := kubernetes.NewStore()
		watcher := kubernetes.NewWatcher(log.Named("watcher"), clientset.CoreV1(), s)
		if err := watcher.WatchEvents(ctx); err != nil {
			log.Fatal(err)
		}
		enricher, err := perisco.NewEnricher(log.Named("enricher"), s)
		if err != nil {
			log.Fatal(err)
		}
		k8sMsgs := enricher.Run(ctx, msgc)
		go exporter.ExportK8S(ctx, k8sMsgs)
	} else {
		go exporter.Export(ctx, msgc)
	}

	<-ctx.Done()
	return nil
}

func splitToSlice(str string) []string {
	return strings.Split(strings.ReplaceAll(str, " ", ""), ",")
}

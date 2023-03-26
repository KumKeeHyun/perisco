package socktest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/signal"
	"sync"
	"syscall"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/logger"
	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	keyCidr  = "cidr"
	keyProto = "proto"
)

func New(vp *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "socktest",
		Short: "test bpf program",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runSockTest(vp)
		},
	}

	flags := cmd.Flags()
	flags.String(keyCidr, "0.0.0.0/0", "CIDR to monitor sevices")
	flags.String(keyProto, "HTTP/2", "Protocol to monitor services")
	vp.BindPFlags(flags)

	return cmd
}

func runSockTest(vp *viper.Viper) error {
	log := logger.DefualtLogger.Named("perisco")

	parse, ok := parseFuncs[vp.GetString(keyProto)]
	if !ok {
		log.Fatalf("invalid proto type(%s)", vp.GetString(keyProto))
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer cancel()

	recvc, sendc, nf, _, clean := bpf.LoadBpfProgram()
	defer clean()

	cidr := vp.GetString(keyCidr)
	if err := nf.RegisterCIDRs([]string{cidr}); err != nil {
		log.Fatal(err)
	}
	log.Infof("network filter will only tract %v", cidr)

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			select {
			case msg := <-recvc:
				parse(msg)
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case msg := <-sendc:
				parse(msg)
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	return nil
}

type parseFunc func(msg *types.MsgEvent)

var parseFuncs = map[string]parseFunc{
	"HTTP/1": parseHTTP1,
	"HTTP/2": parseHTTP2,
}

func parseHTTP1(msg *types.MsgEvent) {

}

var hpackDecs = make(map[types.SockKey]*hpack.Decoder)

func getHpackDec(key *types.SockKey) *hpack.Decoder {
	dec, exists := hpackDecs[*key]
	if !exists {
		dec = hpack.NewDecoder(4096, nil)
		hpackDecs[*key] = dec
	}
	return dec
}

func parseHTTP2(msg *types.MsgEvent) {
	fmt.Printf("parse http/2, flow: %s, len: %d\n%s\n", msg.FlowType.String(), msg.MsgSize, msg.Msg[:msg.MsgSize])

	br := bytes.NewReader(msg.Msg[:msg.MsgSize])
	skipPrefaceIfExists(br)
	f := http2.NewFramer(io.Discard, br)
	f.ReadMetaHeaders = getHpackDec(&msg.SockKey)

	for {
		fr, err := f.ReadFrame()
		if err != nil {
			fmt.Printf("flow: %s, sock: %s, len: %d\nfailed parse frame\n\n", msg.FlowType.String(), msg.SockKey.String(), msg.MsgSize)
			break
		}

		switch fri := fr.(type) {
		case *http2.DataFrame:
			fmt.Printf("flow: %s, sock: %s, len: %d\nheader: %s\ndata: %s\n\n", msg.FlowType.String(), msg.SockKey.String(), msg.MsgSize, fr.Header().String(), fri.Data())
		case *http2.HeadersFrame:
			fmt.Printf("flow: %s, sock: %s, len: %d\nheader: %s\nfrag: %s\n\n", msg.FlowType.String(), msg.SockKey.String(), msg.MsgSize, fr.Header().String(), fri.HeaderBlockFragment())
		case *http2.MetaHeadersFrame:
			fmt.Printf("flow: %s, sock: %s, len: %d\nheader: %s\nfields: %v\n\n", msg.FlowType.String(), msg.SockKey.String(), msg.MsgSize, fr.Header().String(), fri.Fields)
		default:
			fmt.Printf("flow: %s, sock: %s, len: %d\nheader: %s\n\n", msg.FlowType.String(), msg.SockKey.String(), msg.MsgSize, fr.Header().String())
		}
	}
}

func skipPrefaceIfExists(r *bytes.Reader) {
	preface := make([]byte, len(http2.ClientPreface))
	r.Read(preface)
	if !bytes.Equal(preface, []byte(http2.ClientPreface)) {
		r.Seek(0, 0)
	}
}

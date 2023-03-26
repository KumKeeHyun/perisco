package socktest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/signal"
	"strings"
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
	keyCidrs  = "cidrs"
	keyProtos = "protos"
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
	flags.String(keyCidrs, "0.0.0.0/0", "List of cidr to monitor sevices")
	flags.String(keyProtos, "HTTP/1,HTTP/2", "List of protocols to monitor services")
	vp.BindPFlags(flags)

	return cmd
}

func runSockTest(vp *viper.Viper) error {
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

	recvc, sendc, nf, _, clean := bpf.LoadBpfProgram()
	defer clean()

	cidrs := splitToSlice(vp.GetString(keyCidrs))
	if err := nf.RegisterCIDRs(cidrs); err != nil {
		log.Fatal(err)
	}
	log.Infof("network filter will only tract %v", cidrs)

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			select {
			case msg := <-recvc:
				parseHTTP2(msg)
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
				parseHTTP2(msg)
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	return nil
}

func splitToSlice(str string) []string {
	return strings.Split(strings.ReplaceAll(str, " ", ""), ",")
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

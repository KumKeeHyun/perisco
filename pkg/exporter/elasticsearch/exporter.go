package elasticsearch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"github.com/KumKeeHyun/perisco/pkg/host"
	"github.com/KumKeeHyun/perisco/pkg/logger"
	es "github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esutil"
	"google.golang.org/protobuf/encoding/protojson"
)

type ESConfig struct {
	Addresses    string `mapstructure:"EXPORTER_ELASTICSEARCH_ADDRESSES"`
	Username     string `mapstructure:"EXPORTER_ELASTICSEARCH_USERNAME"`
	Password     string `mapstructure:"EXPORTER_ELASTICSEARCH_PASSWORD"`
	CloudID      string `mapstructure:"EXPORTER_ELASTICSEARCH_CLOUDID"`
	APIKey       string `mapstructure:"EXPORTER_ELASTICSEARCH_APIKEY"`
	ServiceToken string `mapstructure:"EXPORTER_ELASTICSEARCH_SERVICETOKEN"`
	Fingerprint  string `mapstructure:"EXPORTER_ELASTICSEARCH_FINGERPRINT"`
}

func (cfg ESConfig) toElasticsearchConfig() (escfg es.Config, err error) {
	escfg.Addresses = strings.Split(cfg.Addresses, ",")
	if escfg.Addresses[0] == "" {
		return escfg, fmt.Errorf("elasticsearch nodes must be set at least one")
	}
	escfg.Username = cfg.Username
	escfg.Password = cfg.Password
	escfg.CloudID = cfg.CloudID
	escfg.APIKey = cfg.APIKey
	escfg.ServiceToken = cfg.ServiceToken
	escfg.CertificateFingerprint = cfg.Fingerprint

	escfg.RetryOnStatus = []int{502, 503, 504, 429}
	escfg.RetryBackoff = func(i int) time.Duration { return time.Duration(i) * 100 * time.Millisecond }
	escfg.MaxRetries = 1

	return escfg, nil
}

type Exporter struct {
	indexer esutil.BulkIndexer
	encoder *protojson.MarshalOptions

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}
}

func New(cfg ESConfig) (*Exporter, error) {
	escfg, err := cfg.toElasticsearchConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create elasticsearch exporter: %w", err)
	}
	esCli, err := es.NewClient(escfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create elasticsearch exporter: %w", err)
	}

	resp, err := esCli.API.Indices.PutIndexTemplate("perisco_k8s_logs_template", strings.NewReader(k8sLogsIndexTemplates))
	if err != nil {
		return nil, fmt.Errorf("failed to request PutIndexTemplate perisco_k8s_logs_template: %w", err)
	}
	if resp.IsError() {
		return nil, fmt.Errorf("PutIndexTemplate perisco_k8s_logs_template error, status=%s", resp.Status())
	}
	resp, err = esCli.API.Indices.PutIndexTemplate("perisco_logs_template", strings.NewReader(logsIndexTemplates))
	if err != nil {
		return nil, fmt.Errorf("failed to request PutIndexTemplate perisco_logs_template: %w", err)
	}
	if resp.IsError() {
		return nil, fmt.Errorf("PutIndexTemplate perisco_logs_template error, status=%s", resp.Status())
	}

	indexer, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
		Client:        esCli,
		NumWorkers:    1,
		FlushInterval: time.Second * 10,
		OnError: func(ctx context.Context, err error) {
			logger.DefualtLogger.Warnf("bulk indexing error: %w", err)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create elasticsearch exporter: %w", err)
	}
	return &Exporter{
		indexer: indexer,
		encoder: &protojson.MarshalOptions{},
	}, nil
}

func (e *Exporter) Export(ctx context.Context, msgc chan *pb.ProtoMessage) {
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.donec = make(chan struct{})

	defer func() {
		e.indexer.Close(e.ctx)
		close(e.donec)
	}()

	hostname := host.MustGetHostname()
	for {
		select {
		case msg := <-msgc:
			b, err := e.encoder.Marshal(msg)
			if err != nil {
				continue
			}
			e.indexer.Add(e.ctx,
				esutil.BulkIndexerItem{
					Action: "index",
					Index:  "perisco-logs-" + hostname,
					Body:   bytes.NewReader(b),
				},
			)
		case <-e.ctx.Done():
			return
		}
	}
}

func (e *Exporter) ExportK8S(ctx context.Context, msgc chan *pb.K8SProtoMessage) {
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.donec = make(chan struct{})

	defer func() {
		e.indexer.Close(e.ctx)
		close(e.donec)
	}()

	hostname := host.MustGetHostname()
	for {
		select {
		case msg := <-msgc:
			b, err := e.encoder.Marshal(msg)
			if err != nil {
				continue
			}
			e.indexer.Add(e.ctx,
				esutil.BulkIndexerItem{
					Action: "index",
					Index:  "perisco-k8s-logs-" + hostname,
					Body:   bytes.NewReader(b),
				},
			)
		case <-e.ctx.Done():
			return
		}
	}
}

func (e *Exporter) Stop() error {
	if e.cancel != nil {
		e.cancel()
	}
	<-e.donec

	err := e.ctx.Err()
	if !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

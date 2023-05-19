package start

import "github.com/spf13/pflag"

const (
	keyCidrs  = "cidrs"
	keyProtos = "protos"

	keyKubernetes           = "kubernetes"
	keyKubernetesMasterUrl  = "kubernetes_master_url"
	keyKubernetesConfigPath = "kubernetes_config_path"

	keyExporter                          = "exporter"
	keyExporterFileName                  = "exporter_file_name"
	keyExporterFilePretty                = "exporter_file_pretty"
	keyExporterElasticsearchAddresses    = "exporter_elasticsearch_addresses"
	keyExporterElasticsearchUsername     = "exporter_elasticsearch_username"
	keyExporterElasticsearchPassword     = "exporter_elasticsearch_password"
	keyExporterElasticsearchCloudID      = "exporter_elasticsearch_cloudid"
	keyExporterElasticsearchAPIKey       = "exporter_elasticsearch_apiKey"
	keyExporterElasticsearchServiceToken = "exporter_elasticsearch_servicetoken"
	keyExporterElasticsearchFingerprint  = "exporter_elasticsearch_fingerprint"
)

func setFlags(flags *pflag.FlagSet) {
	// perisco protocols
	flags.String(keyCidrs, "0.0.0.0/0", "List of cidrs to monitor sevices")
	flags.String(keyProtos, "HTTP/1,HTTP/2", "List of protocols to parse[HTTP/1 | HTTP/2]")

	// kubernetes enricher
	flags.Bool(keyKubernetes, false, "Enable k8s resources enricher")
	flags.String(keyKubernetesMasterUrl, "", "Kubernetes master url")
	flags.String(keyKubernetesConfigPath, "", "Kubernetes kubeconfig path")

	// exporter
	flags.String(keyExporter, "file", "Exporter type[file | elasticsearch]. default: file")
	// exporter file
	flags.String(keyExporterFileName, "", "File exporter target file")
	flags.Bool(keyExporterFilePretty, false, "Enable pretty print")
	// exporter elasticsearch
	flags.String(keyExporterElasticsearchAddresses, "", "list of Elasticsearch nodes to use")
	flags.String(keyExporterElasticsearchUsername, "", "Username for HTTP Basic Authentication")
	flags.String(keyExporterElasticsearchPassword, "", "Password for HTTP Basic Authentication")
	flags.String(keyExporterElasticsearchCloudID, "", "Endpoint for the Elastic Service")
	flags.String(keyExporterElasticsearchAPIKey, "", "Base64-encoded token for authorization")
	flags.String(keyExporterElasticsearchServiceToken, "", "Service token for authorization")
	flags.String(keyExporterElasticsearchFingerprint, "", "fingerprint given by Elasticsearch on first launch")
}

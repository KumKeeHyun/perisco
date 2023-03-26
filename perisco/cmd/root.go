package cmd

import (
	"github.com/KumKeeHyun/perisco/perisco/cmd/run"
	"github.com/KumKeeHyun/perisco/perisco/cmd/socktest"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func New() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "perisco",
		Short: "perisco is a L7 observability solution using eBPF",
	}

	rootCmd.AddCommand(
		run.New(newViper("perisco")),
		socktest.New(newViper("socktest")),
	)
	return rootCmd
}

func newViper(prefix string) *viper.Viper {
	vp := viper.New()
	vp.SetEnvPrefix(prefix)
	vp.AutomaticEnv()
	return vp
}
package cmd

import (
	"github.com/KumKeeHyun/perisco/perisco/cmd/run"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func New() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "perisco",
		Short: "perisco is a L7 observability solution using eBPF",
	}

	vp := newViper()
	rootCmd.AddCommand(
		run.New(vp),
	)
	return rootCmd
}

func newViper() *viper.Viper {
	vp := viper.New()
	vp.SetEnvPrefix("perisco")
	vp.AutomaticEnv()
	return vp
}
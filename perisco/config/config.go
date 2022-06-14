package config

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Cidrs string
}

func (c *Config) CidrSlice() []string {
	cidrs := strings.ReplaceAll(c.Cidrs, " ", "")
	return strings.Split(cidrs, ",")
}

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("perisco")

	viper.BindEnv("cidrs")
	viper.SetDefault("cidrs", "0.0.0.0/0")

	viper.AutomaticEnv()

	config := &Config{}
	viper.Unmarshal(config)

	return config, nil
}

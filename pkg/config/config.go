package config

import (
	"github.com/lacework-dev/aws-security-hub-integration/pkg/log"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// Config stores the application configuration details
type Config struct {
	Logger    loggerConfig
	AWS       awsConfig
	Server    serverConfig
}

// loggerConfig stores the log related configuration
type loggerConfig struct {
	Debug bool
}

// awsConfig stores the AWS related configuration
type awsConfig struct {
	Role	string
	Region  string
}

// serverConfig stores the web related configuration
type serverConfig struct {
	TLSPort      string
	CertFilePath string
	KeyFilePath  string
}

// Init is responsible for initializing the configuration from yaml or ENV
func Init(cfgFile string) {
	// get configuration from environment variables
	viper.SetEnvPrefix("lwsechub")
	viper.SetConfigName("config")
	viper.AddConfigPath(".") // adding home directory as first search path
	viper.AutomaticEnv()     // read in environment variables that match
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}
	err := viper.ReadInConfig()
	if err != nil {
		e, ok := err.(viper.ConfigParseError)
		if ok {
			log.Logger.Fatal(e)
		}
	}

	if viper.Get("logger.debug") == nil {
		viper.Set("logger.debug", false)
	}
	if viper.Get("server.tls_port") == nil {
		viper.Set("server.tls_port", "8443")
	}
	if viper.Get("server.cert_file_path") == nil {
		viper.Set("server.cert_file_path", "")
	}
	if viper.Get("server.cert_key_path") == nil {
		viper.Set("server.cert_key_path", "")
	}
	if viper.Get("aws.role") == nil {
		viper.Set("aws.role", "")
	}
	if viper.Get("aws.region") == nil {
		viper.Set("aws.region", "")
	}
}

// GetConfig is used to pull the configuration into the application
func GetConfig() Config {
	return Config{
		Logger: loggerConfig{Debug: viper.GetBool("logger.debug")},
		AWS: awsConfig{
			Role: viper.GetString("aws.role"),
			Region: viper.GetString("aws.region"),
		},
		Server: serverConfig{
			TLSPort:      viper.GetString("server.tls_port"),
			CertFilePath: viper.GetString("server.cert_file_path"),
			KeyFilePath:  viper.GetString("server.cert_key_path"),
		},
	}
}

// Print outputs the configuration file
func (c *Config) Print() {
	cfgBytes, err := yaml.Marshal(c)
	if err != nil {
		log.Logger.Fatalf("marshalling configuration: %v", err)
	}
	log.Logger.Debugf("%v", string(cfgBytes))
}


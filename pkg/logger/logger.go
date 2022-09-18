package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var DefualtLogger = initDefaultLogger() 

func initDefaultLogger() *zap.SugaredLogger {
	config := zap.NewProductionConfig()
	config.Encoding = "console"
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder 
	encoderConfig.StacktraceKey = ""
	config.EncoderConfig = encoderConfig

	logger, err := config.Build(zap.AddCallerSkip(1))
	if err != nil {
		panic(err)
	}
	return logger.Sugar()
}



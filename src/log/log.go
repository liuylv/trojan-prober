package log

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
)

// Log levels
const (
	LogLevelAll     = iota // 0: All logs
	LogLevelCrucial        // 1: Only crucial logs
)

var logLevel = LogLevelAll

var (
	crucialLogger *log.Logger
	infoLogger    *log.Logger
	debugLogger   *log.Logger
	errorLogger   *log.Logger
)

func init() {
	crucialLogger = log.New(os.Stdout, "", 0)
	infoLogger = log.New(os.Stdout, "", 0)
	debugLogger = log.New(os.Stdout, "", 0)
	errorLogger = log.New(os.Stderr, "", 0)
}

// SetLogLevel sets the global log level
func SetLogLevel(level int) {
	logLevel = level
}

func logMessage(level int, logger *log.Logger, prefix, message string, v ...interface{}) {
	if logLevel <= level {
		timestamp := Colorize(time.Now().Format("2006/01/02 15:04:05"), blue)
		logMessage := fmt.Sprintf(message, v...)
		logger.Printf("%s %s %s\n", prefix, timestamp, logMessage)
	}
}

func Crucial(message interface{}, v ...interface{}) {
	logMessage(LogLevelCrucial, crucialLogger, Colorize("[CRUCIAL]", green), message.(string), v...)
}

func Info(message interface{}, v ...interface{}) {
	logMessage(LogLevelAll, infoLogger, Colorize("[INFO]", cyan), message.(string), v...)
}

func Debug(message interface{}, v ...interface{}) {
	logMessage(LogLevelAll, debugLogger, Colorize("[DEBUG]", purple), message.(string), v...)
}

func Error(message interface{}, v ...interface{}) {
	_, file, line, ok := runtime.Caller(1)
	var logMessage string
	if len(v) > 0 {
		logMessage = fmt.Sprintf(message.(string), v...)
	} else {
		logMessage = fmt.Sprintf("%v", message)
	}

	if ok {
		timestamp := Colorize(time.Now().Format("2006/01/02 15:04:05"), blue)
		fileLocation := Colorize(fmt.Sprintf("%s:%d", file, line), yellow)
		errorLogger.Printf("%s %s %s: %s\n", Colorize("[ERROR]", red), timestamp, fileLocation, logMessage)
	} else {
		errorLogger.Println(logMessage)
	}
	// Terminate the program
	os.Exit(1)
}

// PrintColoredMessage prints a message in a specified color without a timestamp
func PrintColoredMessage(message string, v ...interface{}) {
	// Format the message with the provided arguments
	formattedMessage := fmt.Sprintf(message, v...)

	// Print the colored message to stdout
	fmt.Printf("%s%s%s\n", yellow, formattedMessage, reset)
}

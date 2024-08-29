package log

import (
	"fmt"
)

const (
	reset  = "\033[0m"  // Reset color
	red    = "\033[31m" // Error log
	green  = "\033[32m" // Crucial log
	yellow = "\033[33m" // File location
	blue   = "\033[34m" // Timestamp
	purple = "\033[35m" // Debug log
	cyan   = "\033[36m" // Ingo log
)

// Colorize returns a colored string based on the input color code and text
func Colorize(text, colorCode string) string {
	return fmt.Sprintf("%s%s%s", colorCode, text, reset)
}

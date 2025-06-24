package analyzer

import (
	"fmt"
	"os"
	"strings"
)

// DebugConfig holds debug configuration
type DebugConfig struct {
	Enabled      bool
	Verbose      bool
	ShowAIInput  bool
	ShowAIOutput bool
	ShowParsing  bool
	ShowAnalysis bool
}

// Global debug configuration
var Debug = &DebugConfig{}

// InitDebug initializes debug configuration from environment variables
func InitDebug() {
	debugEnv := strings.ToLower(os.Getenv("DEBUG"))
	Debug.Enabled = debugEnv != "" && debugEnv != "false" && debugEnv != "0"
	Debug.Verbose = strings.Contains(debugEnv, "verbose") || strings.Contains(debugEnv, "v")
	Debug.ShowAIInput = Debug.Enabled && (Debug.Verbose || strings.Contains(debugEnv, "ai"))
	Debug.ShowAIOutput = Debug.Enabled && (Debug.Verbose || strings.Contains(debugEnv, "ai"))
	Debug.ShowParsing = Debug.Enabled && (Debug.Verbose || strings.Contains(debugEnv, "parse"))
	Debug.ShowAnalysis = Debug.Enabled && (Debug.Verbose || strings.Contains(debugEnv, "analysis"))
}

// DebugPrint prints debug messages when debug is enabled
func DebugPrint(format string, args ...interface{}) {
	if Debug.Enabled {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

// DebugPrintf prints debug messages with custom prefix when debug is enabled
func DebugPrintf(prefix, format string, args ...interface{}) {
	if Debug.Enabled {
		fmt.Printf("[DEBUG][%s] "+format, append([]interface{}{prefix}, args...)...)
		fmt.Println()
	}
}

// DebugPrintAI prints AI-related debug messages
func DebugPrintAI(format string, args ...interface{}) {
	if Debug.ShowAIInput || Debug.ShowAIOutput {
		fmt.Printf("[DEBUG][AI] "+format+"\n", args...)
	}
}

// DebugPrintParse prints parsing-related debug messages
func DebugPrintParse(format string, args ...interface{}) {
	if Debug.ShowParsing {
		fmt.Printf("[DEBUG][PARSE] "+format+"\n", args...)
	}
}

// DebugPrintAnalysis prints analysis-related debug messages
func DebugPrintAnalysis(format string, args ...interface{}) {
	if Debug.ShowAnalysis {
		fmt.Printf("[DEBUG][ANALYSIS] "+format+"\n", args...)
	}
}

// DebugPrintStep prints step-by-step debug messages
func DebugPrintStep(step string, format string, args ...interface{}) {
	if Debug.Enabled {
		fmt.Printf("[DEBUG][STEP:%s] "+format, append([]interface{}{step}, args...)...)
		fmt.Println()
	}
}

// DebugPrintError prints error debug messages
func DebugPrintError(context string, err error) {
	if Debug.Enabled {
		fmt.Printf("[DEBUG][ERROR][%s] %v\n", context, err)
	}
}

// DebugPrintJSON prints JSON data in a formatted way
func DebugPrintJSON(prefix, data string) {
	if Debug.Enabled {
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			if strings.TrimSpace(line) != "" {
				fmt.Printf("[DEBUG][%s][%d] %s\n", prefix, i+1, line)
			}
		}
	}
}

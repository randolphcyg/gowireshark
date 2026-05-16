package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/randolphcyg/gowireshark/version"
)

// NewMCPServer creates and configures the MCP server with all tools registered.
func NewMCPServer() *server.MCPServer {
	s := server.NewMCPServer(
		"gowireshark-mcp",
		version.GetVersion(),
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	registerAllTools(s)

	return s
}

// Serve starts the MCP server using stdio transport.
func Serve(s *server.MCPServer) error {
	return server.ServeStdio(s)
}

// --- Path Safety ---

// isSafePath validates that the given path is within the allowed base directory.
func isSafePath(path string) bool {
	pcapBaseDir := os.Getenv("PCAP_BASE_DIR")
	if pcapBaseDir == "" {
		return true // no restriction configured
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absBase, err := filepath.Abs(pcapBaseDir)
	if err != nil {
		return false
	}
	if absPath == absBase {
		return true
	}
	return strings.HasPrefix(absPath, absBase+string(filepath.Separator))
}

// --- Argument Extraction Helpers ---

func getStringArg(request mcp.CallToolRequest, key string) (string, error) {
	val, ok := request.GetArguments()[key]
	if !ok {
		return "", nil
	}
	s, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return s, nil
}

func getRequiredStringArg(request mcp.CallToolRequest, key string) (string, error) {
	val, err := getStringArg(request, key)
	if err != nil {
		return "", err
	}
	if val == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return val, nil
}

func getFloatArg(request mcp.CallToolRequest, key string, defaultVal float64) float64 {
	val, ok := request.GetArguments()[key]
	if !ok {
		return defaultVal
	}
	switch v := val.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	default:
		return defaultVal
	}
}

func getBoolArg(request mcp.CallToolRequest, key string, defaultVal bool) bool {
	val, ok := request.GetArguments()[key]
	if !ok {
		return defaultVal
	}
	if b, ok := val.(bool); ok {
		return b
	}
	return defaultVal
}

// validateFilepath validates and returns the filepath argument.
func validateFilepath(request mcp.CallToolRequest) (string, error) {
	fp, err := getRequiredStringArg(request, "filepath")
	if err != nil {
		return "", err
	}
	if !isSafePath(fp) {
		return "", fmt.Errorf("access denied: path must be under PCAP_BASE_DIR")
	}
	return fp, nil
}

// --- Response Helpers ---

func errorResult(err error) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultError(err.Error()), nil
}

func textResult(jsonStr string) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultText(jsonStr), nil
}

// --- Utility ---

func parseIntList(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid integer %q: %v", p, err)
		}
		result = append(result, n)
	}
	return result, nil
}

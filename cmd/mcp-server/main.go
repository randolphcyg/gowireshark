package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	mcpserver "github.com/randolphcyg/gowireshark/mcp"
	"github.com/randolphcyg/gowireshark/pkg"
	"github.com/randolphcyg/gowireshark/version"
)

func main() {
	// Handle CLI flags
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v", "version":
			fmt.Printf("gowireshark-mcp %s\n", version.GetFullInfo())
			fmt.Printf("Wireshark EPAN: %s\n", pkg.EpanVersion())
			os.Exit(0)
		case "--help", "-h", "help":
			printUsage()
			os.Exit(0)
		}
	}

	log.Printf("gowireshark-mcp %s (epan %s)", version.GetFullInfo(), pkg.EpanVersion())

	baseDir := resolveBaseDir()

	// Configure extract directory
	extractDir := os.Getenv("EXTRACT_FILE_DIR")
	if extractDir == "" {
		extractDir = os.Getenv("EXTRACT_DIR")
	}
	if extractDir == "" {
		extractDir = filepath.Join(baseDir, "extracted_files")
	}
	if !filepath.IsAbs(extractDir) {
		extractDir = filepath.Join(baseDir, extractDir)
	}
	pkg.ExtractFileDir = extractDir

	// Configure pcap base dir
	pcapBaseDir := os.Getenv("PCAP_BASE_DIR")
	if pcapBaseDir != "" && !filepath.IsAbs(pcapBaseDir) {
		pcapBaseDir = filepath.Join(baseDir, pcapBaseDir)
		os.Setenv("PCAP_BASE_DIR", pcapBaseDir)
	}

	// Ensure output directories exist
	os.MkdirAll(extractDir, 0o755)

	log.Printf("Base dir: %s", baseDir)
	log.Printf("Extract dir: %s", extractDir)
	if pcapBaseDir != "" {
		log.Printf("PCAP base dir: %s", pcapBaseDir)
	}

	s := mcpserver.NewMCPServer()

	if err := mcpserver.Serve(s); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`gowireshark-mcp — Wireshark-powered MCP server for AI-assisted packet analysis

USAGE:
  gowireshark-mcp              Start MCP server (stdio transport)
  gowireshark-mcp --version    Show version information
  gowireshark-mcp --help       Show this help

ENVIRONMENT VARIABLES:
  GOWIRESHARK_BASE_DIR   Base directory for relative paths (default: executable dir)
  PCAP_BASE_DIR          Restrict pcap access to this directory (default: unrestricted)
  EXTRACT_FILE_DIR       Output directory for extracted files (default: <base>/extracted_files)

PERMISSIONS (live capture only):
  macOS:  sudo ./install_bpf_permissions.sh
  Linux:  sudo setcap cap_net_raw,cap_net_admin+ep gowireshark-mcp

DOCUMENTATION:
  https://github.com/randolphcyg/gowireshark
`)
}

// resolveBaseDir determines the base directory for resolving relative paths.
func resolveBaseDir() string {
	if dir := os.Getenv("GOWIRESHARK_BASE_DIR"); dir != "" {
		if abs, err := filepath.Abs(dir); err == nil {
			return abs
		}
	}
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			return filepath.Dir(real)
		}
	}
	cwd, _ := os.Getwd()
	return cwd
}

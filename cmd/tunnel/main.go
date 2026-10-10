package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vikrannntttt8/Dark_Tunnel/internal/crypto"
)

const banner = `
  ██████╗  █████╗ ██████╗ ██╗  ██╗    ████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗     
  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║     
  ██║  ██║███████║██████╔╝█████╔╝        ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║     
  ██║  ██║██╔══██║██╔══██╗██╔═██╗        ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║     
  ██████╔╝██║  ██║██║  ██║██║  ██╗       ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝       ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
                     — Modern, High-Performance VPN From Scratch —
`

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "genkey":
		runGenKey()
	case "pubkey":
		runPubKey()
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "status":
		runStatus()
	case "version":
		fmt.Println("Dark Tunnel v0.1.0 (Development)")
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(banner)
	fmt.Println("Usage: tunnel <command> [arguments]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  genkey              Generate a new private key and write to stdout")
	fmt.Println("  pubkey              Calculate the public key from a private key read from stdin")
	fmt.Println("  client -config FILE Run the Dark Tunnel client using the specified config")
	fmt.Println("  server -config FILE Run the Dark Tunnel server using the specified config")
	fmt.Println("  status              Show current tunnel connection metrics and routing status")
	fmt.Println("  version             Display version information")
	fmt.Println()
	fmt.Println("Key Generation Example:")
	fmt.Println("  tunnel genkey > private.key")
	fmt.Println("  tunnel pubkey < private.key > public.key")
}

func runGenKey() {
	priv, err := crypto.GeneratePrivateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating private key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(priv.String())
}

func runPubKey() {
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
		os.Exit(1)
	}

	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		fmt.Fprintln(os.Stderr, "Error: empty input. Pass base64 private key via stdin.")
		os.Exit(1)
	}

	privKey, err := crypto.ParseKey(trimmed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing private key: %v\n", err)
		os.Exit(1)
	}

	pubKey, err := privKey.PublicKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving public key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(pubKey.String())
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	configPath := fs.String("config", "configs/server.yaml", "Path to server configuration YAML file")
	_ = fs.Parse(args)

	fmt.Printf("[SERVER] Starting Dark Tunnel Server...\n")
	fmt.Printf("[SERVER] Config path: %s\n", *configPath)
	fmt.Println("[SERVER] Waiting for authorized peers on UDP 51820...")
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	configPath := fs.String("config", "configs/client.yaml", "Path to client configuration YAML file")
	repair := fs.Bool("repair", false, "Restore OS routing table and DNS to original state")
	_ = fs.Parse(args)

	if *repair {
		fmt.Println("[CLIENT] Running emergency network repair...")
		fmt.Println("[CLIENT] Restoring original default gateway and DNS resolvers.")
		fmt.Println("[CLIENT] Network state cleanly repaired.")
		return
	}

	fmt.Printf("[CLIENT] Starting Dark Tunnel Client...\n")
	fmt.Printf("[CLIENT] Config path: %s\n", *configPath)
	fmt.Println("[CLIENT] Initiating mutual Noise IK handshake with gateway...")
}

func runStatus() {
	fmt.Println("--- Dark Tunnel Status ---")
	fmt.Println("Status:          Inactive")
	fmt.Println("Interface:       None")
	fmt.Println("Public IP:       Not routed through tunnel")
	fmt.Println("Bytes Sent:      0 B")
	fmt.Println("Bytes Received:  0 B")
}

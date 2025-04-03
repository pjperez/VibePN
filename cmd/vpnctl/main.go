package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
)

const socketPath = "/var/run/vibepn.sock"

type CommandRequest struct {
	Cmd string `json:"cmd"`
}

type CommandResponse struct {
	Status string      `json:"status"`
	Output interface{} `json:"output,omitempty"`
	Error  string      `json:"error,omitempty"`
}

func main() {
	jsonMode := flag.Bool("json", false, "Output raw JSON")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [--json] <status|routes|peers>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	req := CommandRequest{Cmd: cmd}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to socket: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send request: %v\n", err)
		os.Exit(1)
	}

	var resp CommandResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read response: %v\n", err)
		os.Exit(1)
	}

	if resp.Status != "ok" {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.Error)
		os.Exit(1)
	}

	if *jsonMode {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp.Output)
		return
	}

	printOutput(cmd, resp.Output)
}

func printOutput(cmd string, output interface{}) {
	switch cmd {
	case "status":
		m, _ := output.(map[string]interface{})
		fmt.Printf("Uptime: %v\n", m["uptime"])
		fmt.Printf("Peers:  %v\n", m["peers"])
		fmt.Printf("Routes: %v\n", m["routes"])
	case "peers":
		peers, _ := output.([]interface{})
		for _, item := range peers {
			p := item.(map[string]interface{})
			fmt.Printf("Peer: %s (last seen: %s)\n", p["id"], p["last_seen"])
		}
	case "routes":
		routes, _ := output.([]interface{})
		for _, item := range routes {
			r := item.(map[string]interface{})
			fmt.Printf("Net: %-10s Prefix: %-18s Peer: %-16s Metric: %v Expires: %s\n",
				r["network"], r["prefix"], r["peer"], r["metric"], r["expires"])
		}
	default:
		fmt.Println("OK")
	}
}

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

var (
	version = "unknown"

	flagVersion      = flag.Bool("version", false, "Print version information and exit")
	flagAuditNetwork = flag.String("audit-network", "tcp", "Network to listen for audit log connections on")
	flagAuditAddr    = flag.String("audit-addr", ":9090", "Address to listen for audit log connections on")
	flagHTTPAddr     = flag.String("http-addr", ":8080", "Address to bind the HTTP server (including /metrics) to")
	flagCacheTTL     = flag.Duration("cache-ttl", 5*time.Minute, "Length of time to cache request timestamps for calculating latency")
	flagCacheCleanup = flag.Duration("cache-cleanup", 1*time.Minute, "Interval at which expired entries in the request timestamp cache are evicted")
)

func main() {
	flag.Parse()

	if *flagVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	processor := NewAuditProcessor(
		*flagAuditNetwork,
		*flagAuditAddr,
		*flagHTTPAddr,
		*flagCacheTTL,
		*flagCacheCleanup,
	)
	log.Fatalln(processor.Start())
}

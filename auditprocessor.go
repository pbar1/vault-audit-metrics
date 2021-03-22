package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/hashicorp/vault/audit"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const PromNamespace = "vaultaudit"

// AuditProcessor contains all of the context needed for processing Vault audit logs into Prometheus metrics.
type AuditProcessor struct {
	auditNetwork     string
	auditAddr        string
	httpAddr         string
	timestamps       *cache.Cache
	gagueCacheSize   *prometheus.GaugeVec
	gagueRequests    *prometheus.GaugeVec
	gagueResponses   *prometheus.GaugeVec
	histogramLatency *prometheus.HistogramVec
}

// NewAuditProcessor constructs an AuditProcessor.
func NewAuditProcessor(auditNetwork, auditAddr, httpAddr string, cacheTTL, cacheCleanup time.Duration) *AuditProcessor {
	p := &AuditProcessor{
		auditNetwork: auditNetwork,
		auditAddr:    auditAddr,
		httpAddr:     httpAddr,
		timestamps:   cache.New(cacheTTL, cacheCleanup),
	}
	p.addMetrics()
	return p
}

// addMetrics defines a set of Prometheus metrics and adds them to the AuditProcessor.
func (p *AuditProcessor) addMetrics() {
	p.gagueCacheSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: PromNamespace,
		Subsystem: "cache",
		Name:      "timestamp_cache_entries_total",
		Help:      "Number of request timestamp entries in the cache.",
	}, nil)
	p.gagueRequests = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: PromNamespace,
		Subsystem: "events",
		Name:      "requests_total",
		Help:      "Number of Vault requests recorded in the audit log. Partitioned by operation, path, and error.",
	},
		[]string{"operation", "path", "error"})
	p.gagueResponses = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: PromNamespace,
		Subsystem: "events",
		Name:      "responses_total",
		Help:      "Number of Vault responses recorded in the audit log. Partitioned by operation, path, and error.",
	},
		[]string{"operation", "path", "error"})
	p.histogramLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: PromNamespace,
		Subsystem: "events",
		Name:      "response_duration_seconds",
		Help:      "Latency of a Vault response. Partitioned by operation, path, and error.",
	},
		[]string{"operation", "path", "error"})
	prometheus.MustRegister(p.gagueCacheSize, p.gagueRequests, p.gagueResponses, p.histogramLatency)
}

// handle parses incoming connections into typed AuditEvents and dispatches them for processing.
func (p *AuditProcessor) handle(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("error closing connection: %v\n", err)
		}
	}()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Bytes()

		// push connection read deadline back by 10 seconds
		if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			log.Printf("error setting connecton read deadline: %v\n", err)
			continue
		}

		entry := new(audit.AuditResponseEntry)
		if err := json.Unmarshal(line, entry); err != nil {
			log.Printf("error unmarshalling audit event: %v\n", err)
			continue
		}

		// dispatch audit event processing to another thread so the connection can close without blocking
		go p.process(&AuditEvent{entry: entry})
	}
}

// process records Prometheus metrics from Vault audit log events.
func (p *AuditProcessor) process(auditEvent *AuditEvent) {
	switch auditEvent.entry.Type {

	case AuditEventTypeRequest:
		p.timestamps.Set(auditEvent.entry.Request.ID, auditEvent.entry.Time, 0)
		obs, err := p.gagueRequests.GetMetricWith(auditEvent.PromLabels())
		if err != nil {
			log.Printf("error getting gagueRequests observer: %v\n", err)
			return
		}
		obs.Inc()

	case AuditEventTypeResponse:
		p.observeLatency(auditEvent)
		obs, err := p.gagueResponses.GetMetricWith(auditEvent.PromLabels())
		if err != nil {
			log.Printf("error getting gagueResponses observer: %v\n", err)
			return
		}
		obs.Inc()

	default:
		log.Printf("unknown audit event type: %s\n", auditEvent.entry.Type)
	}
}

// observeLatency calculates and records the latency between audit log requests and responses with matching IDs.
func (p *AuditProcessor) observeLatency(auditEvent *AuditEvent) {
	requestTimestamp, found := p.timestamps.Get(auditEvent.entry.Request.ID)
	if !found {
		log.Printf("prior request not found for response with request id '%s'\n", auditEvent.entry.Request.ID)
		return
	}

	requestTime, err := time.Parse(time.RFC3339Nano, fmt.Sprint(requestTimestamp))
	if err != nil {
		log.Printf("error parsing request timestamp '%s': %v\n", requestTimestamp, err)
		return
	}
	responseTime, err := time.Parse(time.RFC3339Nano, auditEvent.entry.Time)
	if err != nil {
		log.Printf("error parsing response timestamp '%s': %v\n", auditEvent.entry.Time, err)
		return
	}

	observer, err := p.histogramLatency.GetMetricWith(auditEvent.PromLabels())
	if err != nil {
		log.Printf("error getting histogramLatency observer: %v\n", err)
		return
	}
	observer.Observe(responseTime.Sub(requestTime).Seconds())
}

// monitorTimestampCache continuously updates a metric reflecting the number of items in the request timestamp cache.
func (p *AuditProcessor) monitorTimestampCache() {
	for {
		time.Sleep(10 * time.Second)
		obs, err := p.gagueCacheSize.GetMetricWith(nil)
		if err != nil {
			log.Printf("error getting gagueCacheSize observer: %v\n", err)
		}
		obs.Set(float64(p.timestamps.ItemCount()))
	}
}

// healthz is a health endpoint.
func (p *AuditProcessor) healthz(w http.ResponseWriter, _ *http.Request) {
	if _, err := w.Write([]byte(fmt.Sprintf(`{"timestamp_cache_size":%d}`, p.timestamps.ItemCount()))); err != nil {
		log.Printf("error writing healthz response: %v", err)
	}
}

// Start initiates the AuditProcessor, which includes a server listening for Vault audit log connections, as well as an
// HTTP server that exposes metrics and status.
func (p *AuditProcessor) Start() error {
	// Start the HTTP endpoint
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/healthz", p.healthz)
	go func() {
		log.Fatalln(http.ListenAndServe(p.httpAddr, nil))
	}()

	// keep timestamp cache metrics up to date
	go p.monitorTimestampCache()

	// Create audit log processing server
	listener, err := net.Listen(p.auditNetwork, p.auditAddr)
	if err != nil {
		return err
	}
	defer func() {
		if err := listener.Close(); err != nil {
			panic(err)
		}
	}()

	// Listen for and handle incoming Vault audit log events
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("error accepting connection: %v\n", err)
			continue
		}
		go p.handle(conn)
	}
}

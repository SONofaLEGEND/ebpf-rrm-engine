// agent/metrics.go — Phase 4: ring buffer drop counter added

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	apChannelUtil   prometheus.GaugeVec
	apUtilEWMA      prometheus.GaugeVec
	apNoise         prometheus.GaugeVec
	apClients       prometheus.GaugeVec
	apConsecHigh    prometheus.GaugeVec
	eventsTotal     prometheus.CounterVec
	fastloopLatency prometheus.Histogram
	ringbufDrops    prometheus.Gauge
	invalidRFPkts   prometheus.Gauge
	regViolations   prometheus.Counter
	registry        *prometheus.Registry
	server          *http.Server
}

func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{registry: reg}

	m.apChannelUtil = *prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rrm_ap_channel_util_percent",
		Help: "Raw channel utilisation percent (last packet)",
	}, []string{"ap_id"})

	m.apUtilEWMA = *prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rrm_ap_util_ewma_percent",
		Help: "EWMA-smoothed channel utilisation (alpha=0.25, computed in XDP kernel)",
	}, []string{"ap_id"})

	m.apNoise = *prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rrm_ap_noise_floor_dbm",
		Help: "Noise floor dBm (signed, -100 to -60 typical)",
	}, []string{"ap_id"})

	m.apClients = *prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rrm_ap_client_count",
		Help: "Associated clients per AP",
	}, []string{"ap_id"})

	m.apConsecHigh = *prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rrm_ap_consec_high",
		Help: "Consecutive high-utilisation intervals (resets on drop below threshold)",
	}, []string{"ap_id"})

	m.eventsTotal = *prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "rrm_events_total",
		Help: "Total fast-path RRM events by type",
	}, []string{"event_type"})

	// Latency histogram: the key metric for demonstrating fast-loop advantage.
	// Buckets in microseconds: covers 10µs–50ms range.
	// Sub-millisecond fast-loop response should land in 100–2500µs buckets.
	// Slow-loop comparison: 500,000µs (500ms) — off the chart.
	m.fastloopLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "rrm_fastloop_latency_us",
		Help:    "Kernel bpf_ktime_get_ns() to agent receipt latency (microseconds). P50/P95/P99 demonstrate the fast-loop advantage over the 500ms slow-loop polling cycle.",
		Buckets: []float64{10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 50000},
	})

	m.ringbufDrops = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "rrm_ringbuf_drops_total",
		Help: "Events dropped due to ring buffer full",
	})

	m.invalidRFPkts = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "rrm_invalid_rf_packets_total",
		Help: "Packets dropped due to invalid RF parameters",
	})

	m.regViolations = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "rrm_regulatory_violations_total",
		Help: "Total number of DFS regulatory compliance violations detected",
	})

	for _, t := range []string{"DFS", "LOAD_ANOMALY", "NOISE_SPIKE"} {
		m.eventsTotal.WithLabelValues(t)
	}

	reg.MustRegister(
		&m.apChannelUtil, &m.apUtilEWMA, &m.apNoise,
		&m.apClients, &m.apConsecHigh, &m.eventsTotal,
		m.fastloopLatency, m.ringbufDrops, m.invalidRFPkts,
		m.regViolations,
	)
	return m
}

func (m *Metrics) ObserveEvent(r EventRecord) {
	m.eventsTotal.WithLabelValues(EventTypeName(r.Event.EventType)).Inc()
	if r.LatencyNs > 0 {
		m.fastloopLatency.Observe(float64(r.LatencyNs) / 1000.0)
	}
}

func (m *Metrics) UpdateAPGauges(snap APSnapshot) {
	id := strconv.Itoa(int(snap.APID))
	m.apChannelUtil.WithLabelValues(id).Set(float64(snap.Info.ChannelUtil))
	m.apUtilEWMA.WithLabelValues(id).Set(float64(snap.Info.UtilEwmaQ8))
	m.apNoise.WithLabelValues(id).Set(float64(snap.Info.NoiseFloorDbm))
	m.apClients.WithLabelValues(id).Set(float64(snap.Info.ClientCount))
	m.apConsecHigh.WithLabelValues(id).Set(float64(snap.Info.ConsecHigh))
}

func (m *Metrics) IncRegulatoryViolations() {
	m.regViolations.Inc()
}

// UpdateGlobalStats reads the global BPF statistics and syncs them to Prometheus.
func (m *Metrics) UpdateGlobalStats(statsMap interface {
	Lookup(interface{}, interface{}) error
}) {
	if statsMap == nil {
		return
	}
	var drops uint64
	if err := statsMap.Lookup(uint32(StatRingbufDrops), &drops); err == nil {
		m.ringbufDrops.Set(float64(drops))
	}
	var invalid uint64
	if err := statsMap.Lookup(uint32(StatInvalidRFPkts), &invalid); err == nil {
		m.invalidRFPkts.Set(float64(invalid))
	}
}

func (m *Metrics) StartMetricsServer(addr string) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	m.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("[metrics] http://localhost%s/metrics", addr)
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[metrics] error: %v", err)
		}
	}()
}

func (m *Metrics) StopMetricsServer(ctx context.Context) {
	if m.server != nil {
		_ = m.server.Shutdown(ctx)
	}
}

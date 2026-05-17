// agent/state.go
// Thread-safe shared state for fast-loop, slow-loop, dashboard, metrics, CLI.

package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type EventRecord struct {
	ReceivedAt time.Time
	KernelNs   uint64
	LatencyNs  int64
	Synthetic  bool
	Event      RRMEvent
}

func (r EventRecord) LatencyUs() float64 { return float64(r.LatencyNs) / 1000.0 }

type APSnapshot struct {
	APID      uint32
	Info      APInfo
	PktCount  uint64
	UpdatedAt time.Time
}

type Store struct {
	mu             sync.RWMutex
	events         []EventRecord
	maxEvents      int
	apSnapshots    map[uint32]APSnapshot
	eventCounts    [3]uint64
	totalLatencyNs int64
	latencyCount   int64
	startTime      time.Time
}

func NewStore(maxEvents int) *Store {
	return &Store{
		maxEvents:   maxEvents,
		apSnapshots: make(map[uint32]APSnapshot),
		startTime:   time.Now(),
	}
}

func (s *Store) AddEvent(r EventRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) >= s.maxEvents {
		copy(s.events, s.events[1:])
		s.events = s.events[:len(s.events)-1]
	}
	s.events = append(s.events, r)
	if int(r.Event.EventType) < len(s.eventCounts) {
		s.eventCounts[r.Event.EventType]++
	}
	if r.LatencyNs > 0 {
		s.totalLatencyNs += r.LatencyNs
		s.latencyCount++
	}
}

// Events returns newest-first copy for display.
func (s *Store) Events() []EventRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]EventRecord, len(s.events))
	for i, r := range s.events {
		out[len(s.events)-1-i] = r
	}
	return out
}

func (s *Store) EventCounts() [3]uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.eventCounts
}

func (s *Store) TotalEvents() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

func (s *Store) AvgLatencyUs() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.latencyCount == 0 {
		return 0
	}
	return float64(s.totalLatencyNs) / float64(s.latencyCount) / 1000.0
}

func (s *Store) UpdateAPSnapshot(snap APSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apSnapshots[snap.APID] = snap
}

func (s *Store) APSnapshots() []APSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]APSnapshot, 0, len(s.apSnapshots))
	for _, snap := range s.apSnapshots {
		out = append(out, snap)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].APID < out[j].APID })
	return out
}

func (s *Store) APCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.apSnapshots)
}

func (s *Store) Summary() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counts := s.eventCounts
	total := len(s.events)
	avgUs := 0.0
	if s.latencyCount > 0 {
		avgUs = float64(s.totalLatencyNs) / float64(s.latencyCount) / 1000.0
	}
	uptime := time.Since(s.startTime)
	h := int(uptime.Hours())
	m := int(uptime.Minutes()) % 60
	sec := int(uptime.Seconds()) % 60
	return fmt.Sprintf(
		" APs: %d  |  Events: %d (DFS:%d LOAD:%d NOISE:%d)  |  Avg latency: %.1fµs  |  Uptime: %02d:%02d:%02d ",
		len(s.apSnapshots), total,
		counts[EventDFS], counts[EventLoadAnomaly], counts[EventNoiseSpike],
		avgUs, h, m, sec,
	)
}

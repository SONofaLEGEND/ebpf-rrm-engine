package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// BPF filesystem pin directory.
// Maps pinned here persist after the agent process exits (until unpin or reboot).
const BPFPinDir = "/sys/fs/bpf/rrm"

// Wire types — must match kern/rrm_maps.h exactly.

type RRMEvent struct {
	TimestampNs   uint64
	ApID          uint32
	EventType     uint8
	Channel       uint8
	UtilSnapshot  uint8
	NoiseSnapshot int8
}

type APInfo struct {
	Channel       uint8
	ChannelUtil   uint8
	NoiseFloorDbm int8
	ClientCount   uint8
	EventFlags    uint8
	UtilEwmaQ8    uint8
	NoisePrevDbm  int8
	ConsecHigh    uint8
}

type Thresholds struct {
	UtilHigh   uint8
	UtilConsec uint8
	NoiseDelta uint8
	Pad        uint8
}

// Event type constants
const (
	EventDFS          uint8 = 0
	EventLoadAnomaly  uint8 = 1
	EventNoiseSpike   uint8 = 2
	EventRegViolation uint8 = 3
)

// BPF global stats indexes
const (
	StatRingbufDrops  = 0
	StatInvalidRFPkts = 1
)

func EventTypeName(t uint8) string {
	switch t {
	case EventDFS:
		return "DFS"
	case EventLoadAnomaly:
		return "LOAD_ANOMALY"
	case EventNoiseSpike:
		return "NOISE_SPIKE"
	case EventRegViolation:
		return "REG_VIOLATION"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

func EventTypeColour(t uint8) string {
	switch t {
	case EventDFS:
		return "\033[1;31m"
	case EventLoadAnomaly:
		return "\033[1;33m"
	case EventNoiseSpike:
		return "\033[1;36m"
	case EventRegViolation:
		return "\033[1;35m" // Purple/Magenta
	default:
		return "\033[0m"
	}
}

// BPFHandle owns all kernel BPF resources.
type BPFHandle struct {
	Collection  *ebpf.Collection
	XDPLink     link.Link
	RingReader  *ringbuf.Reader
	PktCountMap *ebpf.Map
	APStateMap  *ebpf.Map
	ThreshMap   *ebpf.Map
	EventsMap   *ebpf.Map
	StatsMap    *ebpf.Map
}

// Close releases all kernel resources in the correct order.
func (h *BPFHandle) Close() {
	if h.RingReader != nil {
		h.RingReader.Close()
	}
	if h.XDPLink != nil {
		h.XDPLink.Close()
	}
	if h.Collection != nil {
		h.Collection.Close()
	}
}

// PinMaps pins all BPF maps to the BPF filesystem.
// Creates BPFPinDir if it does not exist.
// Idempotent: overwrites existing pins.
func (h *BPFHandle) PinMaps() error {
	if err := os.MkdirAll(BPFPinDir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", BPFPinDir, err)
	}

	pins := map[string]*ebpf.Map{
		"ap_pkt_count":  h.PktCountMap,
		"ap_state":      h.APStateMap,
		"ap_thresholds": h.ThreshMap,
		"rrm_events":    h.EventsMap,
		"rrm_stats":     h.StatsMap,
	}

	for name, m := range pins {
		path := filepath.Join(BPFPinDir, name)
		// Remove stale pin if it exists (from a previous agent run)
		_ = os.Remove(path)
		if err := m.Pin(path); err != nil {
			return fmt.Errorf("pin map %s to %s: %w", name, path, err)
		}
	}
	return nil
}

// UnpinMaps removes all pinned maps from the BPF filesystem.
// Called on clean shutdown.
func UnpinMaps() {
	names := []string{"ap_pkt_count", "ap_state", "ap_thresholds",
		"rrm_events", "rrm_stats"}
	for _, name := range names {
		path := filepath.Join(BPFPinDir, name)
		_ = os.Remove(path)
	}
	// Remove the directory if empty
	_ = os.Remove(BPFPinDir)
}

// OpenPinnedMaps opens BPF maps from the BPF filesystem without loading
// the BPF object. Used by the CLI when the agent is already running.
func OpenPinnedMaps() (*BPFHandle, error) {
	h := &BPFHandle{}
	pins := map[string]**ebpf.Map{
		"ap_pkt_count":  &h.PktCountMap,
		"ap_state":      &h.APStateMap,
		"ap_thresholds": &h.ThreshMap,
		"rrm_events":    &h.EventsMap,
		"rrm_stats":     &h.StatsMap,
	}
	for name, ptr := range pins {
		path := filepath.Join(BPFPinDir, name)
		m, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			// Close any already-opened maps
			h.Close()
			return nil, fmt.Errorf("open pinned map %s: %w\n"+
				"  Is the agent running? Start with: sudo make run", name, err)
		}
		*ptr = m
	}
	return h, nil
}

// LoadBPF loads the BPF object, writes thresholds, attaches XDP,
// pins maps, and opens the ring buffer reader.
func LoadBPF(cfg *Config) (*BPFHandle, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("RemoveMemlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(cfg.BPFObj)
	if err != nil {
		return nil, fmt.Errorf("LoadCollectionSpec(%q): %w", cfg.BPFObj, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("NewCollection (verifier): %w", err)
	}

	h := &BPFHandle{Collection: coll}

	mapRefs := map[string]**ebpf.Map{
		"ap_pkt_count":  &h.PktCountMap,
		"ap_state":      &h.APStateMap,
		"ap_thresholds": &h.ThreshMap,
		"rrm_events":    &h.EventsMap,
		"rrm_stats":     &h.StatsMap,
	}
	for name, ptr := range mapRefs {
		m, ok := coll.Maps[name]
		if !ok {
			h.Close()
			return nil, fmt.Errorf("map %q not found in BPF collection", name)
		}
		*ptr = m
	}

	// Write thresholds
	thresh := Thresholds{
		UtilHigh:   cfg.UtilHigh,
		UtilConsec: cfg.UtilConsec,
		NoiseDelta: cfg.NoiseDelta,
	}
	if err := h.ThreshMap.Put(uint32(0), thresh); err != nil {
		h.Close()
		return nil, fmt.Errorf("write thresholds: %w", err)
	}

	// Initialize global stats to zero
	for i := uint32(0); i < 2; i++ {
		if err := h.StatsMap.Put(i, uint64(0)); err != nil {
			h.Close()
			return nil, fmt.Errorf("init stats map index %d: %w", i, err)
		}
	}

	// Attach XDP
	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("InterfaceByName(%q): %w", cfg.Iface, err)
	}
	prog, ok := coll.Programs["rrm_xdp_parser"]
	if !ok {
		h.Close()
		return nil, fmt.Errorf("program rrm_xdp_parser not found")
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("AttachXDP(%s): %w\n"+
			"  If busy: sudo ip link set dev %s xdpgeneric off",
			cfg.Iface, err, cfg.Iface)
	}
	h.XDPLink = l

	// Pin maps to BPF filesystem
	if err := h.PinMaps(); err != nil {
		h.Close()
		return nil, fmt.Errorf("PinMaps: %w", err)
	}

	// Open ring buffer reader
	rd, err := ringbuf.NewReader(h.EventsMap)
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("ringbuf.NewReader: %w", err)
	}
	h.RingReader = rd

	return h, nil
}

// Helpers

func GetBootTimeNs() (uint64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, fmt.Errorf("read /proc/stat: %w", err)
	}
	var btime uint64
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("btime ")) {
			if _, err := fmt.Sscanf(string(line), "btime %d", &btime); err == nil {
				return btime * 1e9, nil
			}
		}
	}
	return 0, fmt.Errorf("btime not found in /proc/stat")
}

func WriteThresholds(m *ebpf.Map, t Thresholds) error {
	return m.Put(uint32(0), t)
}

func ReadThresholds(m *ebpf.Map) (Thresholds, error) {
	var t Thresholds
	if err := m.Lookup(uint32(0), &t); err != nil {
		return t, fmt.Errorf("lookup ap_thresholds: %w", err)
	}
	return t, nil
}

// ReadDropCount reads the ring buffer drop counter from rrm_stats.
func ReadDropCount(m *ebpf.Map) (uint64, error) {
	var count uint64
	if err := m.Lookup(uint32(StatRingbufDrops), &count); err != nil {
		return 0, err
	}
	return count, nil
}

// ReadInvalidRFCount reads the invalid RF packet counter from rrm_stats.
func ReadInvalidRFCount(m *ebpf.Map) (uint64, error) {
	var count uint64
	if err := m.Lookup(uint32(StatInvalidRFPkts), &count); err != nil {
		return 0, err
	}
	return count, nil
}

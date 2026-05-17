// agent/dashboard.go
//
// Terminal UI dashboard using rivo/tview.
//
// Layout:
//   ┌────────────────────────────────┬──────────────────────────────────┐
//   │  AP State Table (slow-loop)    │  Event Log (fast-loop)           │
//   │  AP | CH | RAW | EWMA | ...   │  14:23:15 AP2 DFS ch6 847µs     │
//   │   1 |  1 |  38 |  36  | ...   │  14:23:31 AP3 LOAD ch11 1.2ms   │
//   │  ...                          │  ...                             │
//   ├────────────────────────────────┴──────────────────────────────────┤
//   │  Status: APs:5 | Events:7 | Avg latency:1.2µs | Uptime:00:02:34 │
//   └───────────────────────────────────────────────────────────────────┘
//
// tview threading rule: ALL mutations to tview widgets must happen either:
//   a) in the main tview goroutine (via app.QueueUpdateDraw), or
//   b) from within a tview event handler.
//
// The slow-loop and fast-loop goroutines update tview via app.QueueUpdateDraw,
// which queues a function for execution on the tview goroutine.
// This is the ONLY safe way to update tview from external goroutines.

package main

import (
	"fmt"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Dashboard holds all tview widget references.
type Dashboard struct {
	app        *tview.Application
	apTable    *tview.Table
	eventLog   *tview.TextView
	statusBar  *tview.TextView
	store      *Store
	stopTicker chan struct{}
}

// NewDashboard creates the tview layout and wires up the store.
// Does NOT start the application — call Run() for that.
func NewDashboard(store *Store) *Dashboard {
	app := tview.NewApplication()

	d := &Dashboard{
		app:        app,
		store:      store,
		stopTicker: make(chan struct{}),
	}

	// ── AP State Table ──────────────────────────────────────────────────────
	apTable := tview.NewTable().
		SetBorders(false).
		SetSelectable(false, false).
		SetFixed(1, 0) // freeze header row

	apTable.SetBorder(true).
		SetTitle(" AP State  [slow-loop] ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(tview.Styles.SecondaryTextColor)

	// Draw header row
	headers := []string{"AP", "CH", "RAW%", "EWMA%", "NOISE", "CLIENTS", "PKTS", "CONSEC"}
	for col, h := range headers {
		apTable.SetCell(0, col, tview.NewTableCell(h).
			SetTextColor(tview.Styles.SecondaryTextColor).
			SetAlign(tview.AlignRight).
			SetSelectable(false))
	}
	d.apTable = apTable

	// ── Event Log ────────────────────────────────────────────────────────────
	eventLog := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWordWrap(false).
		SetChangedFunc(func() { app.Draw() })

	eventLog.SetBorder(true).
		SetTitle(" Event Log  [fast-loop] ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(tview.Styles.SecondaryTextColor)

	eventLog.SetText("[gray]Waiting for events...[white]\n")
	d.eventLog = eventLog

	// ── Status Bar ────────────────────────────────────────────────────────────
	statusBar := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(false)

	statusBar.SetBorder(false).
		SetBackgroundColor(tview.Styles.MoreContrastBackgroundColor)

	statusBar.SetText(" Starting...")
	d.statusBar = statusBar

	// ── Layout ────────────────────────────────────────────────────────────────
	// Horizontal split: AP table (left 60%) | Event log (right 40%)
	mainRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(apTable, 0, 6, false).
		AddItem(eventLog, 0, 4, false)

	// Vertical split: main content | status bar (1 row)
	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(mainRow, 0, 1, false).
		AddItem(statusBar, 1, 0, false)

	app.SetRoot(root, true).EnableMouse(false)

	// Quit on 'q' or Ctrl+C
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'q' {
			app.Stop()
		}
		return event
	})

	return d
}

// Run starts the tview event loop (blocks until app.Stop() is called).
// Call this from the main goroutine.
func (d *Dashboard) Run() error {
	// Start the refresh ticker in a background goroutine.
	// It queues table + status updates via app.QueueUpdateDraw.
	go d.refreshLoop()
	return d.app.Run()
}

// Stop signals the dashboard's ticker goroutine and stops the tview app.
func (d *Dashboard) Stop() {
	close(d.stopTicker)
	d.app.Stop()
}

// refreshLoop drives periodic UI updates from outside the tview goroutine.
// Runs at 2Hz (500ms) to match the slow-loop poll interval.
func (d *Dashboard) refreshLoop() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopTicker:
			return
		case <-ticker.C:
			// app.QueueUpdateDraw schedules the function on the tview goroutine
			// and redraws after it completes. Safe to call from any goroutine.
			d.app.QueueUpdateDraw(func() {
				d.updateAPTable()
				d.updateStatusBar()
			})

			// Event log: update separately so newest events appear immediately
			d.app.QueueUpdateDraw(func() {
				d.updateEventLog()
			})
		}
	}
}

// updateAPTable rebuilds the AP state table from the Store.
// Must be called from the tview goroutine (via QueueUpdateDraw).
func (d *Dashboard) updateAPTable() {
	snaps := d.store.APSnapshots()

	// Clear all data rows (keep header at row 0)
	for d.apTable.GetRowCount() > 1 {
		d.apTable.RemoveRow(1)
	}

	for i, snap := range snaps {
		row := i + 1
		apIDStr := fmt.Sprintf("%d", snap.APID)

		// Colour EWMA column based on utilisation level
		ewmaColour := "white"
		switch {
		case snap.Info.UtilEwmaQ8 >= 85:
			ewmaColour = "red"
		case snap.Info.UtilEwmaQ8 >= 65:
			ewmaColour = "yellow"
		}

		// Colour noise column based on level
		noiseColour := "white"
		if snap.Info.NoiseFloorDbm > -70 {
			noiseColour = "yellow"
		}
		if snap.Info.NoiseFloorDbm > -60 {
			noiseColour = "red"
		}

		cols := []struct {
			text   string
			colour string
		}{
			{apIDStr, "white"},
			{fmt.Sprintf("%d", snap.Info.Channel), "white"},
			{fmt.Sprintf("%d%%", snap.Info.ChannelUtil), "white"},
			{fmt.Sprintf("%d%%", snap.Info.UtilEwmaQ8), ewmaColour},
			{fmt.Sprintf("%ddBm", snap.Info.NoiseFloorDbm), noiseColour},
			{fmt.Sprintf("%d", snap.Info.ClientCount), "white"},
			{fmt.Sprintf("%d", snap.PktCount), "gray"},
			{fmt.Sprintf("%d", snap.Info.ConsecHigh), "white"},
		}

		for col, c := range cols {
			cell := tview.NewTableCell(c.text).
				SetTextColor(tcell.GetColor(c.colour)).
				SetAlign(tview.AlignRight)
			d.apTable.SetCell(row, col, cell)
		}
	}
}

// updateEventLog rewrites the event log text view from the Store.
// Shows the 30 most recent events, newest first.
// Must be called from the tview goroutine.
func (d *Dashboard) updateEventLog() {
	events := d.store.Events()
	if len(events) == 0 {
		return
	}

	// Cap display to 30 events
	maxDisplay := 30
	if len(events) > maxDisplay {
		events = events[:maxDisplay]
	}

	var text string
	for _, rec := range events {
		// tview colour tags: [colour]text[white]
		var typeTag, typePad string
		switch rec.Event.EventType {
		case EventDFS:
			typeTag = "[red]"
			typePad = "DFS        "
		case EventLoadAnomaly:
			typeTag = "[yellow]"
			typePad = "LOAD_ANOMALY"
		case EventNoiseSpike:
			typeTag = "[cyan]"
			typePad = "NOISE_SPIKE "
		default:
			typeTag = "[white]"
			typePad = fmt.Sprintf("TYPE(%d)    ", rec.Event.EventType)
		}

		synthTag := ""
		if rec.Synthetic {
			synthTag = "[gray](injected)[white] "
		}

		line := fmt.Sprintf("%s[white] AP[::b]%03d[::] %s%-12s[white] ch%-3d util%-4d%% lat[green]%.1fµs[white] %s\n",
			rec.ReceivedAt.Format("15:04:05.000"),
			rec.Event.ApID,
			typeTag, typePad,
			rec.Event.Channel,
			rec.Event.UtilSnapshot,
			rec.LatencyUs(),
			synthTag,
		)
		text += line
	}

	d.eventLog.SetText(text)
	// Scroll to top so newest events (which are listed first) are visible
	d.eventLog.ScrollToBeginning()
}

// updateStatusBar refreshes the one-line summary footer.
// Must be called from the tview goroutine.
func (d *Dashboard) updateStatusBar() {
	d.statusBar.SetText("[white]" + d.store.Summary())
}

// NotifyNewEvent is called by the fast-loop goroutine when a new event arrives.
// Schedules an immediate event log redraw without waiting for the ticker.
// This is what makes the fast-loop visually distinct from the slow-loop:
// the event log updates immediately, the AP table waits for the next tick.
func (d *Dashboard) NotifyNewEvent() {
	d.app.QueueUpdateDraw(func() {
		d.updateEventLog()
		d.updateStatusBar()
	})
}

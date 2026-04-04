package dashboard

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const refreshInterval = 1 * time.Second

// tickMsg triggers a data collection cycle.
type tickMsg time.Time

// snapshotMsg delivers a collected snapshot to the model.
type snapshotMsg Snapshot

// Model is the bubbletea model for the dashboard.
type Model struct {
	collector *Collector
	snapshot  Snapshot
	width     int
	height    int
	quitting  bool
}

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12"))

	sectionStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("14"))

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8"))

	valueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15"))

	greenStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10"))

	yellowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("11"))

	redStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8"))

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("8"))
)

// NewModel creates the bubbletea model wired to a Collector.
func NewModel(collector *Collector) Model {
	return Model{
		collector: collector,
	}
}

// Init returns the initial command.
func (m Model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), tea.WindowSize())
}

// Update handles incoming messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		return m, m.collectCmd()

	case snapshotMsg:
		m.snapshot = Snapshot(msg)
		return m, tickCmd()
	}

	return m, nil
}

// View renders the split-screen dashboard.
func (m Model) View() string {
	if m.quitting {
		return ""
	}
	if m.width == 0 || m.height == 0 {
		return "Initializing dashboard..."
	}

	leftWidth := m.width/2 - 2
	rightWidth := m.width - leftWidth - 3
	contentHeight := m.height - 2

	left := m.renderRequestLog(leftWidth, contentHeight)
	right := m.renderStats(rightWidth, contentHeight)

	leftPane := borderStyle.Width(leftWidth).Height(contentHeight).Render(left)
	rightPane := borderStyle.Width(rightWidth).Height(contentHeight).Render(right)

	return lipgloss.JoinHorizontal(lipgloss.Top, leftPane, rightPane)
}

// tickCmd returns a tea.Cmd that fires after the refresh interval.
func tickCmd() tea.Cmd {
	return tea.Tick(refreshInterval, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// collectCmd runs collection in a goroutine and returns the result.
func (m Model) collectCmd() tea.Cmd {
	return func() tea.Msg {
		maxRows := m.height - 6
		if maxRows < 10 {
			maxRows = 10
		}
		return snapshotMsg(m.collector.Collect(maxRows))
	}
}

// renderRequestLog renders the left pane: recent requests table.
func (m Model) renderRequestLog(width, height int) string {
	var b strings.Builder

	b.WriteString(titleStyle.Render(" Incoming Requests"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(fmt.Sprintf(" Total: %d  Req/s: %.1f",
		m.snapshot.TotalRequests, m.snapshot.RequestsPerSec)))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(" " + strings.Repeat("─", width-2)))
	b.WriteString("\n")

	header := fmt.Sprintf(" %-8s %-6s %-*s %6s %7s",
		"Time", "Method", max(width-34, 10), "Path", "Status", "Latency")
	b.WriteString(labelStyle.Render(header))
	b.WriteString("\n")

	if len(m.snapshot.RecentRequests) == 0 {
		b.WriteString(dimStyle.Render("\n  Waiting for requests..."))
	}

	maxRows := height - 5
	for i, e := range m.snapshot.RecentRequests {
		if i >= maxRows {
			break
		}
		ts := e.Timestamp.Format("15:04:05")
		path := truncate(e.Path, max(width-34, 10))
		status := statusString(e.StatusCode)
		latency := formatLatency(e.Latency)

		row := fmt.Sprintf(" %-8s %-6s %-*s %6s %7s",
			ts, e.Method, max(width-34, 10), path, status, latency)
		b.WriteString(row)
		if i < maxRows-1 {
			b.WriteString("\n")
		}
	}

	return b.String()
}

// renderStats renders the right pane.
func (m Model) renderStats(width, height int) string {
	var b strings.Builder

	b.WriteString(titleStyle.Render(" Server Stats"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(" " + strings.Repeat("─", width-2)))
	b.WriteString("\n")

	// Server section
	b.WriteString(m.renderServerSection(width))
	b.WriteString("\n")

	// Pool section
	b.WriteString(m.renderPoolSection(width))
	b.WriteString("\n")

	// Sessions section
	b.WriteString(m.renderSessionSection(width))
	b.WriteString("\n")

	// Top domains section
	remaining := height - strings.Count(b.String(), "\n") - 3
	b.WriteString(m.renderDomainSection(width, remaining))

	return b.String()
}

func (m Model) renderServerSection(width int) string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render(" Server"))
	b.WriteString("\n")

	uptime := formatDuration(m.snapshot.Uptime)
	b.WriteString(fmt.Sprintf("  %s %s   %s %s\n",
		labelStyle.Render("Uptime:"), valueStyle.Render(uptime),
		labelStyle.Render("Req/s:"), valueStyle.Render(fmt.Sprintf("%.1f", m.snapshot.RequestsPerSec))))
	b.WriteString(fmt.Sprintf("  %s %s   %s %s\n",
		labelStyle.Render("Total:"), valueStyle.Render(fmt.Sprintf("%d", m.snapshot.TotalRequests)),
		labelStyle.Render("Goroutines:"), valueStyle.Render(fmt.Sprintf("%d", m.snapshot.Goroutines))))
	b.WriteString(fmt.Sprintf("  %s %s",
		labelStyle.Render("Memory:"), valueStyle.Render(fmt.Sprintf("%.0f MB", m.snapshot.HeapAllocMB))))
	return b.String()
}

func (m Model) renderPoolSection(width int) string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render(" Pool"))
	b.WriteString("\n")

	availColor := greenStyle
	if m.snapshot.PoolAvailable == 0 {
		availColor = redStyle
	}
	b.WriteString(fmt.Sprintf("  %s/%s %s\n",
		availColor.Render(fmt.Sprintf("%d", m.snapshot.PoolAvailable)),
		valueStyle.Render(fmt.Sprintf("%d", m.snapshot.PoolSize)),
		labelStyle.Render("available")))
	b.WriteString(fmt.Sprintf("  %s %s   %s %s   %s %s",
		labelStyle.Render("Acquired:"), valueStyle.Render(fmt.Sprintf("%d", m.snapshot.PoolAcquired)),
		labelStyle.Render("Recycled:"), valueStyle.Render(fmt.Sprintf("%d", m.snapshot.PoolRecycled)),
		labelStyle.Render("Errors:"), errorCountStyle(m.snapshot.PoolErrors)))
	return b.String()
}

func (m Model) renderSessionSection(width int) string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render(" Sessions"))
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("  %s %s",
		valueStyle.Render(fmt.Sprintf("%d", m.snapshot.SessionCount)),
		labelStyle.Render("active")))

	if m.snapshot.SessionCount > 0 && m.snapshot.SessionCount <= 5 {
		ids := strings.Join(m.snapshot.SessionIDs, ", ")
		b.WriteString(fmt.Sprintf("  %s", dimStyle.Render(truncate(ids, width-16))))
	}
	return b.String()
}

func (m Model) renderDomainSection(width, maxRows int) string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render(fmt.Sprintf(" Domains (%d)", m.snapshot.DomainCount)))
	b.WriteString("\n")

	if len(m.snapshot.TopDomains) == 0 {
		b.WriteString(dimStyle.Render("  No domains tracked yet"))
		return b.String()
	}

	domainWidth := max(width-30, 10)
	header := fmt.Sprintf("  %-*s %6s %6s %7s",
		domainWidth, "Domain", "Reqs", "OK %", "Latency")
	b.WriteString(labelStyle.Render(header))
	b.WriteString("\n")

	for i, ds := range m.snapshot.TopDomains {
		if i >= maxRows-2 {
			break
		}
		domain := truncate(ds.Domain, domainWidth)
		rateStyle := greenStyle
		if ds.SuccessRate < 80 {
			rateStyle = redStyle
		} else if ds.SuccessRate < 95 {
			rateStyle = yellowStyle
		}
		row := fmt.Sprintf("  %-*s %6d %s %7s",
			domainWidth, domain,
			ds.RequestCount,
			rateStyle.Render(fmt.Sprintf("%5.0f%%", ds.SuccessRate)),
			formatMs(ds.AvgLatencyMs))
		b.WriteString(row)
		if i < len(m.snapshot.TopDomains)-1 && i < maxRows-3 {
			b.WriteString("\n")
		}
	}

	return b.String()
}

// --- Helpers ---

func statusString(code int) string {
	s := fmt.Sprintf("%d", code)
	switch {
	case code >= 500:
		return redStyle.Render(s)
	case code >= 400:
		return yellowStyle.Render(s)
	case code >= 300:
		return dimStyle.Render(s)
	default:
		return greenStyle.Render(s)
	}
}

func errorCountStyle(count int64) string {
	s := fmt.Sprintf("%d", count)
	if count > 0 {
		return redStyle.Render(s)
	}
	return valueStyle.Render(s)
}

func formatLatency(d time.Duration) string {
	switch {
	case d >= time.Minute:
		return fmt.Sprintf("%.0fm", d.Minutes())
	case d >= time.Second:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
}

func formatMs(ms int64) string {
	if ms >= 60000 {
		return fmt.Sprintf("%.0fm", float64(ms)/60000)
	}
	if ms >= 1000 {
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	}
	return fmt.Sprintf("%dms", ms)
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

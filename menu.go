package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

type MenuAction struct {
	Command string
	Hotkey  string
	Title   string
	Detail  string
	Hint    string
	Color   string
}

var interactiveMenuActions = []MenuAction{
	{Command: "daemon", Hotkey: "1", Title: "Always-On Engine", Detail: "Keep collecting every 15m while tests continue in the background queue.", Hint: "Main production mode.", Color: "1;35"},
	{Command: "once", Hotkey: "2", Title: "One-Time Cycle", Detail: "Collect, parse, test, write, and sync a single full pass.", Hint: "Good for a manual refresh.", Color: "1;36"},
	{Command: "check", Hotkey: "3", Title: "Health Check", Detail: "Check APIs, cores, Telegram, GitHub, and source reachability.", Hint: "Startup diagnostics.", Color: "1;32"},
	{Command: "resources", Hotkey: "4", Title: "Resources", Detail: "Browse configured sources, runtime paths, and current service switches.", Hint: "Read-only overview.", Color: "1;34"},
	{Command: "settings", Hotkey: "5", Title: "Settings", Detail: "Toggle key runtime switches in config.json directly from the CLI.", Hint: "Arrow keys + Enter + S.", Color: "1;33"},
	{Command: "telegram-login", Hotkey: "6", Title: "Telegram Login", Detail: "Refresh Telegram session interactively.", Hint: "Use when session expires.", Color: "1;33"},
	{Command: "reindex", Hotkey: "7", Title: "Rebuild Outputs", Detail: "Rewrite categorized files from saved state and sync GitHub.", Hint: "No source scrape.", Color: "1;34"},
	{Command: "exit", Hotkey: "8", Title: "Exit", Detail: "Close the CLI control deck.", Hint: "Quit safely.", Color: "1;31"},
}

func shouldUseInteractiveMenu() bool {
	return len(os.Args) == 1 && isInteractiveTerminal()
}

func isInteractiveTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func promptInteractiveCommand(cfg Config, state *State, message string) (string, error) {
	if !isInteractiveTerminal() {
		return "once", nil
	}
	if !prepareConsolePlatform() {
		return "once", nil
	}
	fd := int(os.Stdin.Fd())
	previousState, err := term.MakeRaw(fd)
	if err != nil {
		return "once", nil
	}
	defer func() {
		_ = term.Restore(fd, previousState)
		fmt.Print("\x1b[?25h\x1b[0m\x1b[?1049l")
	}()
	fmt.Print("\x1b[?1049h\x1b[?25l")

	selected := 0
	for {
		fmt.Print(renderInteractiveMenu(cfg, state, selected, message))
		key, err := readMenuKey()
		if err != nil {
			return "", err
		}
		switch {
		case key == "up":
			selected = moveMenuSelection(selected, -2, len(interactiveMenuActions))
		case key == "down":
			selected = moveMenuSelection(selected, 2, len(interactiveMenuActions))
		case key == "left":
			selected = moveMenuSelectionHorizontal(selected, -1, len(interactiveMenuActions))
		case key == "right":
			selected = moveMenuSelectionHorizontal(selected, 1, len(interactiveMenuActions))
		case key == "prev":
			selected = moveMenuSelection(selected, -1, len(interactiveMenuActions))
		case key == "next":
			selected = moveMenuSelection(selected, 1, len(interactiveMenuActions))
		case key == "enter":
			return interactiveMenuActions[selected].Command, nil
		case key == "quit":
			return "exit", nil
		default:
			for _, action := range interactiveMenuActions {
				if key == action.Hotkey {
					return action.Command, nil
				}
				if strings.EqualFold(key, action.Command) {
					return action.Command, nil
				}
			}
		}
	}
}

func renderInteractiveMenu(cfg Config, state *State, selected int, message string) string {
	snapshot := snapshotState(cfg, state)
	var b strings.Builder
	now := time.Now()
	selectedAction := interactiveMenuActions[selected]
	b.WriteString("\x1b[?25l\x1b[H\x1b[2J")
	b.WriteString(colorize("1;36", "╔══════════════════════════════════════════════════════════════════════════════╗"))
	b.WriteByte('\n')
	header := fmt.Sprintf("║ ProxyHarvest Control Deck %s  Local: %s", spinnerFrame(now), now.Format("2006-01-02 15:04:05"))
	b.WriteString(padRightANSI(header, 79) + colorize("1;36", "║"))
	b.WriteByte('\n')
	b.WriteString(colorize("1;36", "╠══════════════════════════════════════════════════════════════════════════════╣"))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("Fleet     %s  %s  %s  %s  Sources:%d", statBadge("TOTAL", snapshot.Total, "37"), statBadge("PING", snapshot.Pinged, "32"), statBadge("SAFE", snapshot.SecurityTested, "36"), statBadge("REJ", snapshot.Rejected, "31"), snapshot.SourceConfigured)))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("Runtime   %s  %s  %s  %s  %s", menuBoolBadge("XRAY", fileExists(cfg.Cores.XrayPath)), menuBoolBadge("SING", fileExists(cfg.Cores.SingBoxPath)), menuBoolBadge("TG", telegramAPIConfigured(cfg) && fileExists(telegramSessionFile(cfg))), menuBoolBadge("GH", cfg.GitHub.Enabled && cfg.GitHub.Token != "" && cfg.GitHub.Repository != ""), menuBoolBadge("TCP", cfg.Probes.EnableTCPPrecheck))))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("Schedule  Source:%dm  Retest:%dh  GitHub:%dm  Last source:%s", cfg.Schedule.SourceCheckEveryMinutes, cfg.Schedule.RetestEveryHours, cfg.GitHub.SyncEveryMinutes, statusAgeLabel(state.LastSourceCheck))))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("History   Last GitHub:%s  State:%s", statusAgeLabel(state.LastGitHubSync), trimForDisplay(cfg.Paths.StateFile, 34))))
	b.WriteByte('\n')
	b.WriteString(colorize("1;36", "╠══════════════════════════════════════════════════════════════════════════════╣"))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(colorize("1;35", "Command Palette  |  Use arrows or H/J/K/L, Enter to run, Q to exit")))
	b.WriteByte('\n')
	for row := 0; row < len(interactiveMenuActions); row += 2 {
		left := renderMenuCard(interactiveMenuActions[row], selected == row, 36)
		right := renderMenuCard(interactiveMenuActions[row+1], selected == row+1, 36)
		for line := 0; line < len(left); line++ {
			b.WriteString(wrapBoxLine(left[line] + "  " + right[line]))
			b.WriteByte('\n')
		}
	}
	b.WriteString(colorize("1;36", "╠══════════════════════════════════════════════════════════════════════════════╣"))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("Selected  %s", colorize(selectedAction.Color, selectedAction.Title))))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("Details   %s", trimForDisplay(selectedAction.Detail, 64))))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("Hint      %s", trimForDisplay(selectedAction.Hint, 64))))
	b.WriteByte('\n')
	if strings.TrimSpace(message) == "" {
		message = "Ready. Pick a command and press Enter."
	}
	b.WriteString(wrapBoxLine(fmt.Sprintf("Status    %s", trimForDisplay(message, 64))))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(colorize("2;37", "Tip       Settings can toggle TCP precheck, fallbacks, GitHub sync, and verbose console.")))
	b.WriteByte('\n')
	b.WriteString(colorize("1;36", "╚══════════════════════════════════════════════════════════════════════════════╝"))
	return b.String()
}

func renderMenuCard(action MenuAction, selected bool, width int) []string {
	if width < 24 {
		width = 24
	}
	borderColor := "2;37"
	titleColor := action.Color
	marker := " "
	if selected {
		borderColor = "1;37"
		titleColor = "1;30;47"
		marker = ">"
	}
	titleText := fmt.Sprintf("%s [%s] %s", marker, action.Hotkey, action.Title)
	detailText := trimForDisplay(action.Detail, width-4)
	hintText := trimForDisplay(action.Hint, width-4)
	lines := []string{
		colorize(borderColor, "┌"+strings.Repeat("─", width-2)+"┐"),
		colorize(borderColor, "│") + padRightANSI(colorize(titleColor, " "+trimForDisplay(titleText, width-4)+" "), width-2) + colorize(borderColor, "│"),
		colorize(borderColor, "│") + padRightANSI(" "+detailText+" ", width-2) + colorize(borderColor, "│"),
		colorize(borderColor, "│") + padRightANSI(colorize("2;37", " "+hintText+" "), width-2) + colorize(borderColor, "│"),
		colorize(borderColor, "└"+strings.Repeat("─", width-2)+"┘"),
	}
	return lines
}

func menuBoolBadge(label string, ok bool) string {
	if ok {
		return colorize("1;32", label+":READY")
	}
	return colorize("1;31", label+":MISS")
}

func moveMenuSelection(current, delta, total int) int {
	next := current + delta
	if next < 0 {
		next = current
	}
	if next >= total {
		next = current
	}
	return next
}

func moveMenuSelectionHorizontal(current, delta, total int) int {
	next := current + delta
	if next < 0 || next >= total {
		return current
	}
	if current/2 != next/2 {
		return current
	}
	return next
}

func readMenuKey() (string, error) {
	buf := make([]byte, 8)
	n, err := os.Stdin.Read(buf)
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	return decodeMenuKeyData(buf[:n]), nil
}

func decodeMenuKeyData(data []byte) string {
	events := decodeMenuKeyEvents(data)
	if len(events) > 0 {
		return events[0]
	}
	return strings.TrimSpace(string(data))
}

func decodeMenuKeyEvents(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	events := make([]string, 0, len(data))
	for i := 0; i < len(data); i++ {
		switch {
		case i+2 < len(data) && data[i] == 0x1b && data[i+1] == '[':
			switch data[i+2] {
			case 'A':
				events = append(events, "up")
			case 'B':
				events = append(events, "down")
			case 'C':
				events = append(events, "right")
			case 'D':
				events = append(events, "left")
			}
			i += 2
		case i+1 < len(data) && (data[i] == 0 || data[i] == 224):
			switch data[i+1] {
			case 72:
				events = append(events, "up")
			case 80:
				events = append(events, "down")
			case 75:
				events = append(events, "left")
			case 77:
				events = append(events, "right")
			}
			i++
		case data[i] == '\r' || data[i] == '\n':
			events = append(events, "enter")
		case data[i] == 'q' || data[i] == 'Q' || data[i] == 0x1b:
			events = append(events, "quit")
		case data[i] == 'k' || data[i] == 'K' || data[i] == 'w' || data[i] == 'W':
			events = append(events, "up")
		case data[i] == 'j' || data[i] == 'J':
			events = append(events, "down")
		case data[i] == 'h' || data[i] == 'H' || data[i] == 'a' || data[i] == 'A':
			events = append(events, "left")
		case data[i] == 'l' || data[i] == 'L' || data[i] == 'd' || data[i] == 'D':
			events = append(events, "right")
		case data[i] >= '1' && data[i] <= '9':
			events = append(events, string(data[i]))
		case data[i] == ' ':
			events = append(events, " ")
		case data[i] >= 33 && data[i] <= 126:
			events = append(events, string(data[i]))
		}
	}
	return events
}

func statusAgeLabel(value string) string {
	last, ok := parseTime(value)
	if !ok {
		return "never"
	}
	return formatDurationShort(time.Since(last)) + " ago"
}

func setupRuntimeInput(ui *LiveUI) (func(), *RuntimeController) {
	controller := &RuntimeController{}
	if !isInteractiveTerminal() {
		return nil, controller
	}
	fd := int(os.Stdin.Fd())
	previousState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, controller
	}
	go func() {
		buf := make([]byte, 8)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				return
			}
			for _, key := range decodeMenuKeyEvents(buf[:n]) {
				stop, section, line := applyRuntimeKey(controller, key)
				if ui != nil && line != "" {
					ui.Log(section, line)
				}
				if stop {
					return
				}
			}
		}
	}()
	restore := func() {
		_ = term.Restore(fd, previousState)
	}
	return restore, controller
}

func applyRuntimeKey(controller *RuntimeController, key string) (bool, string, string) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	switch key {
	case "p", "P", " ":
		controller.paused = !controller.paused
		return false, "scheduler", ternaryString(controller.paused, "tester paused from keyboard", "tester resumed from keyboard")
	case "r", "R":
		controller.forceRefresh = true
		return false, "source", "manual source refresh queued"
	case "c", "C":
		controller.healthCheck = true
		return false, "scheduler", "manual health check queued"
	case "g", "G":
		controller.forceRefresh = true
		controller.healthCheck = true
		return false, "github", "refresh + health check queued"
	case "quit":
		controller.stopRequested = true
		return true, "scheduler", "stop requested from keyboard"
	default:
		return false, "", ""
	}
}

type settingItem struct {
	Label  string
	Value  func(*Config) bool
	Toggle func(*Config)
	Detail string
}

func showSettingsScreen(configPath string, cfg Config) (bool, error) {
	if !isInteractiveTerminal() || !prepareConsolePlatform() {
		return false, nil
	}
	items := []settingItem{
		{
			Label:  "TCP precheck before URL test",
			Value:  func(c *Config) bool { return c.Probes.EnableTCPPrecheck },
			Toggle: func(c *Config) { c.Probes.EnableTCPPrecheck = !c.Probes.EnableTCPPrecheck },
			Detail: "When on, TCP runs first for TCP-based configs. Only reachable endpoints continue to real delay.",
		},
		{
			Label:  "Probe URL fallback chain",
			Value:  func(c *Config) bool { return c.Probes.FallbackProbeURLs },
			Toggle: func(c *Config) { c.Probes.FallbackProbeURLs = !c.Probes.FallbackProbeURLs },
			Detail: "When off, only the first configured ping/speed/IP URL is used.",
		},
		{
			Label:  "Try all probe URLs",
			Value:  func(c *Config) bool { return c.Probes.UseAllProbeURLs },
			Toggle: func(c *Config) { c.Probes.UseAllProbeURLs = !c.Probes.UseAllProbeURLs },
			Detail: "When on, all probe URLs are tried instead of stopping on the first success.",
		},
		{
			Label:  "GitHub sync enabled",
			Value:  func(c *Config) bool { return c.GitHub.Enabled },
			Toggle: func(c *Config) { c.GitHub.Enabled = !c.GitHub.Enabled },
			Detail: "Controls whether categorized outputs are pushed to GitHub.",
		},
		{
			Label:  "Verbose console logs",
			Value:  func(c *Config) bool { return c.Logging.ConsoleVerbose },
			Toggle: func(c *Config) { c.Logging.ConsoleVerbose = !c.Logging.ConsoleVerbose },
			Detail: "Shows more progress logs in the terminal outside log files.",
		},
	}
	fd := int(os.Stdin.Fd())
	previousState, err := term.MakeRaw(fd)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = term.Restore(fd, previousState)
		fmt.Print("\x1b[?25h\x1b[0m\x1b[?1049l")
	}()
	fmt.Print("\x1b[?1049h\x1b[?25l")
	localCfg := cfg
	selected := 0
	status := "Enter toggles. S saves. Q exits."
	for {
		fmt.Print(renderSettingsScreen(localCfg, items, selected, status))
		key, err := readMenuKey()
		if err != nil {
			return false, err
		}
		switch key {
		case "up", "prev":
			selected = moveMenuSelection(selected, -1, len(items))
		case "down", "next":
			selected = moveMenuSelection(selected, 1, len(items))
		case "enter":
			items[selected].Toggle(&localCfg)
			status = "Value updated. Press S to write config.json."
		case "s", "S":
			fillDefaults(&localCfg)
			if err := writeJSON(configPath, localCfg); err != nil {
				status = "Save failed: " + trimForDisplay(err.Error(), 42)
			} else {
				status = "config.json updated."
				return true, nil
			}
		case "quit":
			return false, nil
		}
	}
}

func renderSettingsScreen(cfg Config, items []settingItem, selected int, status string) string {
	var b strings.Builder
	b.WriteString("\x1b[?25l\x1b[H\x1b[2J")
	b.WriteString(colorize("1;33", "╔══════════════════════════════════════════════════════════════════════════════╗"))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(colorize("1;33", "Settings  |  Up/Down to move, Enter to toggle, S to save, Q to return")))
	b.WriteByte('\n')
	b.WriteString(colorize("1;33", "╠══════════════════════════════════════════════════════════════════════════════╣"))
	b.WriteByte('\n')
	for idx, item := range items {
		marker := " "
		style := "2;37"
		if idx == selected {
			marker = ">"
			style = "1;37"
		}
		value := menuBoolBadge("STATE", item.Value(&cfg))
		b.WriteString(wrapBoxLine(fmt.Sprintf("%s %s  %s", colorize(style, marker), colorize(style, trimForDisplay(item.Label, 42)), value)))
		b.WriteByte('\n')
	}
	b.WriteString(colorize("1;33", "╠══════════════════════════════════════════════════════════════════════════════╣"))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(trimForDisplay(items[selected].Detail, 66)))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("Source timer: %dm   Retest: %dh   TCP timeout: %dms", cfg.Schedule.SourceCheckEveryMinutes, cfg.Schedule.RetestEveryHours, cfg.Probes.TCPPrecheckTimeoutMS)))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("Status: %s", trimForDisplay(status, 60))))
	b.WriteByte('\n')
	b.WriteString(colorize("1;33", "╚══════════════════════════════════════════════════════════════════════════════╝"))
	return b.String()
}

func showResourcesScreen(cfg Config, state *State) error {
	if !isInteractiveTerminal() || !prepareConsolePlatform() {
		return nil
	}
	fd := int(os.Stdin.Fd())
	previousState, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer func() {
		_ = term.Restore(fd, previousState)
		fmt.Print("\x1b[?25h\x1b[0m\x1b[?1049l")
	}()
	fmt.Print("\x1b[?1049h\x1b[?25l")
	selected := 0
	lines := buildResourceLines(cfg, state)
	for {
		fmt.Print(renderResourcesScreen(lines, selected))
		key, err := readMenuKey()
		if err != nil {
			return err
		}
		switch key {
		case "up", "prev":
			selected = moveMenuSelection(selected, -1, len(lines))
		case "down", "next":
			selected = moveMenuSelection(selected, 1, len(lines))
		case "quit", "enter":
			return nil
		}
	}
}

func buildResourceLines(cfg Config, state *State) []string {
	lines := []string{
		fmt.Sprintf("State file: %s", cfg.Paths.StateFile),
		fmt.Sprintf("GitHub repo: %s", fallback(cfg.GitHub.Repository, "disabled")),
		fmt.Sprintf("Configs dir: %s", cfg.Paths.ConfigsDir),
		fmt.Sprintf("TCP precheck: %s", ternaryString(cfg.Probes.EnableTCPPrecheck, "enabled", "disabled")),
		fmt.Sprintf("Probe fallbacks: %s", ternaryString(cfg.Probes.FallbackProbeURLs, "enabled", "disabled")),
		fmt.Sprintf("Cores: xray=%s sing-box=%s", cfg.Cores.XrayPath, cfg.Cores.SingBoxPath),
		fmt.Sprintf("Telegram session: %s", telegramSessionFile(cfg)),
		fmt.Sprintf("Records in state: %d", len(state.Records)),
		"Enabled sources:",
	}
	for _, source := range cfg.Sources {
		if !source.Enabled {
			continue
		}
		target := source.Channel
		if target == "" && len(source.Links) > 0 {
			target = source.Links[0]
		}
		lines = append(lines, fmt.Sprintf("- %s [%s] %s", source.Name, source.Type, trimForDisplay(target, 42)))
	}
	return lines
}

func renderResourcesScreen(lines []string, selected int) string {
	var b strings.Builder
	b.WriteString("\x1b[?25l\x1b[H\x1b[2J")
	b.WriteString(colorize("1;34", "╔══════════════════════════════════════════════════════════════════════════════╗"))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(colorize("1;34", "Resources  |  Up/Down to browse, Enter or Q to return")))
	b.WriteByte('\n')
	b.WriteString(colorize("1;34", "╠══════════════════════════════════════════════════════════════════════════════╣"))
	b.WriteByte('\n')
	start := 0
	if selected > 10 {
		start = selected - 10
	}
	end := start + 14
	if end > len(lines) {
		end = len(lines)
	}
	for idx := start; idx < end; idx++ {
		prefix := "  "
		style := "2;37"
		if idx == selected {
			prefix = "> "
			style = "1;37"
		}
		b.WriteString(wrapBoxLine(colorize(style, trimForDisplay(prefix+lines[idx], 66))))
		b.WriteByte('\n')
	}
	for i := end - start; i < 14; i++ {
		b.WriteString(wrapBoxLine(colorize("2;37", "…")))
		b.WriteByte('\n')
	}
	b.WriteString(colorize("1;34", "╚══════════════════════════════════════════════════════════════════════════════╝"))
	return b.String()
}

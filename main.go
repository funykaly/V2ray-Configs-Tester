package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

const (
	defaultConfigFile   = "config.json"
	defaultStateFile    = ".state/state.json"
	defaultLogsDir      = ".logs"
	supportedSchemeExpr = `(anytls|blackhole|block|custom|direct|dns|dokodemo-door|freedom|http|https|hy2|hy|hysteria2|hysteria|json|juicity|mixed|naive|redirect|selector|shadowtls|ssh|ssr|ss|socks5|socks4a|socks4|socks|tap|tailscale|tor|trojan|tproxy|tun|tuic|urltest|vless|vmess|wg|wireguard)`
)

var (
	supportedLinkProtocols = map[string]struct{}{
		"anytls":        {},
		"blackhole":     {},
		"block":         {},
		"custom":        {},
		"dns":           {},
		"dokodemo-door": {},
		"direct":        {},
		"freedom":       {},
		"http":          {},
		"https":         {},
		"hy":            {},
		"hy2":           {},
		"hysteria":      {},
		"hysteria2":     {},
		"juicity":       {},
		"naive":         {},
		"shadowtls":     {},
		"ssh":           {},
		"ss":            {},
		"ssr":           {},
		"selector":      {},
		"socks":         {},
		"socks4":        {},
		"socks4a":       {},
		"socks5":        {},
		"tap":           {},
		"tailscale":     {},
		"tor":           {},
		"trojan":        {},
		"tproxy":        {},
		"tun":           {},
		"tuic":          {},
		"urltest":       {},
		"vless":         {},
		"vmess":         {},
		"wg":            {},
		"wireguard":     {},
		"redirect":      {},
		"mixed":         {},
		"json":          {},
	}
	privateIPPatterns = []*regexp.Regexp{
		regexp.MustCompile(`^127\.`),
		regexp.MustCompile(`^10\.`),
		regexp.MustCompile(`^192\.168\.`),
		regexp.MustCompile(`^169\.254\.`),
		regexp.MustCompile(`^172\.(1[6-9]|2[0-9]|3[0-1])\.`),
	}
	base64OnlyPattern = regexp.MustCompile(`^[A-Za-z0-9+/_=\-\s\r\n]+$`)
	linkSchemePattern = regexp.MustCompile(`(?i)` + supportedSchemeExpr + `://`)
	urlPattern        = regexp.MustCompile(`(?i)` + supportedSchemeExpr + `:\/\/[^\s"'<>]+`)
	emojiRiskMap      = map[string]string{
		"risk":        "🔴",
		"safe":        "🟢",
		"low risk":    "🟡",
		"medium risk": "🟠",
		"unknown":     "⚪",
		"rejected":    "🔴",
	}
	localGeoReader     *maxminddb.Reader
	localGeoPath       string
	localGeoErr        error
	localGeoCityReader *maxminddb.Reader
	localGeoCityPath   string
	localGeoCityErr    error
)

type Config struct {
	Sources  []SourceSpec   `json:"sources"`
	Telegram TelegramConfig `json:"telegram"`
	GitHub   GitHubConfig   `json:"github"`
	Schedule ScheduleConfig `json:"schedule"`
	Probes   ProbeConfig    `json:"probes"`
	Cores    CoreConfig     `json:"cores"`
	Logging  LoggingConfig  `json:"logging"`
	Paths    PathsConfig    `json:"paths"`
}

type SourceSpec struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Enabled bool     `json:"enabled"`
	Channel string   `json:"channel,omitempty"`
	Links   []string `json:"links,omitempty"`
}

type TelegramConfig struct {
	APIID      int    `json:"api_id"`
	APIHash    string `json:"api_hash"`
	Session    string `json:"session_name"`
	UseWebOnly bool   `json:"use_web_only"`
}

type GitHubConfig struct {
	Enabled          bool   `json:"enabled"`
	Token            string `json:"token"`
	Repository       string `json:"repository"`
	Branch           string `json:"branch"`
	BasePath         string `json:"base_path"`
	SyncEveryMinutes int    `json:"sync_every_minutes"`
}

type ScheduleConfig struct {
	SourceCheckEveryMinutes int `json:"source_check_every_minutes"`
	RetestEveryHours        int `json:"retest_every_hours"`
}

type ProbeConfig struct {
	TimeoutSeconds         int                   `json:"timeout_seconds"`
	PingURLs               []string              `json:"ping_urls"`
	SpeedURLs              []string              `json:"speed_urls"`
	SecurityProbes         []ActiveSecurityProbe `json:"security_probes"`
	GeoLookupURLs          []string              `json:"geo_lookup_urls"`
	ProxyGeoURLs           []string              `json:"proxy_geo_urls"`
	ProxyIPURLs            []string              `json:"proxy_ip_urls"`
	LocalGeoDB             string                `json:"local_geo_db"`
	LocalGeoCityDB         string                `json:"local_geo_city_db"`
	SpeedTestBytes         int64                 `json:"speed_test_bytes"`
	FastSpeedMBps          float64               `json:"fast_speed_mbps"`
	MediumSpeedMBps        float64               `json:"medium_speed_mbps"`
	EnableTCPPrecheck      bool                  `json:"enable_tcp_precheck"`
	TCPPrecheckTimeoutMS   int                   `json:"tcp_precheck_timeout_ms"`
	FallbackProbeURLs      bool                  `json:"fallback_probe_urls"`
	UseAllProbeURLs        bool                  `json:"use_all_probe_urls"`
	PerConfigTimeoutMS     int                   `json:"per_config_timeout_ms"`
	CoreStartupWaitMS      int                   `json:"core_startup_wait_ms"`
	SecurityProbeTimeoutMS int                   `json:"security_probe_timeout_ms"`
	EnableProxyGeoLookup   bool                  `json:"enable_proxy_geo_lookup"`
}

type ActiveSecurityProbe struct {
	Name                 string            `json:"name"`
	URL                  string            `json:"url"`
	Method               string            `json:"method"`
	Headers              map[string]string `json:"headers"`
	ExpectHeaders        map[string]string `json:"expect_headers"`
	RejectHeaders        map[string]string `json:"reject_headers"`
	ExpectStatus         int               `json:"expect_status"`
	ExpectContentType    string            `json:"expect_content_type"`
	ExpectContains       []string          `json:"expect_contains"`
	RejectContains       []string          `json:"reject_contains"`
	ExpectSHA256         string            `json:"expect_sha256"`
	RejectSHA256         []string          `json:"reject_sha256"`
	ExpectMinBytes       int64             `json:"expect_min_bytes"`
	ExpectMaxBytes       int64             `json:"expect_max_bytes"`
	RejectRedirect       bool              `json:"reject_redirect"`
	MaxRedirects         int               `json:"max_redirects"`
	AllowedRedirectHosts []string          `json:"allowed_redirect_hosts"`
	Severity             string            `json:"severity"`
	CompareGroup         string            `json:"compare_group"`
	Critical             bool              `json:"critical"`
	Penalty              int               `json:"penalty"`
}

type CoreConfig struct {
	XrayPath    string `json:"xray_path"`
	SingBoxPath string `json:"singbox_path"`
}

type LoggingConfig struct {
	ConsoleVerbose bool                  `json:"console_verbose"`
	Directory      string                `json:"directory"`
	Sections       map[string]SectionLog `json:"sections"`
}

type SectionLog struct {
	FileEnabled bool `json:"file_enabled"`
}

type PathsConfig struct {
	StateFile         string `json:"state_file"`
	ConfigsDir        string `json:"configs_dir"`
	CountryDir        string `json:"country_dir"`
	ProtocolDir       string `json:"protocol_dir"`
	SecurityDir       string `json:"security_dir"`
	SpeedDir          string `json:"speed_dir"`
	AllScrapedFile    string `json:"all_scraped_file"`
	AllWorkingFile    string `json:"all_working_file"`
	AllSecureFile     string `json:"all_secure_file"`
	AllScrapedDir     string `json:"all_scraped_dir"`
	SecurityTestDir   string `json:"security_test_dir"`
	AllPingedFile     string `json:"all_pinged_file"`
	AllSecurityTested string `json:"all_security_tested_file"`
}

type State struct {
	LastSourceCheck string                 `json:"last_source_check"`
	LastGitHubSync  string                 `json:"last_github_sync"`
	Sources         map[string]SourceState `json:"sources"`
	Records         map[string]*Record     `json:"records"`
	LastSyncedFiles []string               `json:"last_synced_files"`
}

type SourceState struct {
	Hash          string `json:"hash"`
	LastSuccessAt string `json:"last_success_at"`
	LastError     string `json:"last_error"`
}

type Record struct {
	EndpointKey            string         `json:"endpoint_key"`
	ID                     string         `json:"id"`
	Protocol               string         `json:"protocol"`
	Raw                    string         `json:"raw"`
	NamedRaw               string         `json:"named_raw"`
	Host                   string         `json:"host"`
	Port                   int            `json:"port"`
	Remarks                string         `json:"remarks"`
	Country                string         `json:"country"`
	CountryCode            string         `json:"country_code"`
	Flag                   string         `json:"flag"`
	StateName              string         `json:"state_name"`
	LatencyMS              int            `json:"latency_ms"`
	SpeedMBps              float64        `json:"speed_mbps"`
	SecurityLevel          string         `json:"security_level"`
	SecurityScore          int            `json:"security_score"`
	SecurityIssues         []string       `json:"security_issues"`
	Active                 bool           `json:"active"`
	PingOK                 bool           `json:"ping_ok"`
	Rejected               bool           `json:"rejected"`
	RejectReason           string         `json:"reject_reason"`
	Unsupported            bool           `json:"unsupported"`
	UnsupportedReason      string         `json:"unsupported_reason"`
	OutboundIP             string         `json:"outbound_ip"`
	LastSeenAt             string         `json:"last_seen_at"`
	LastURLTestAt          string         `json:"last_url_test_at"`
	LastSecurityAt         string         `json:"last_security_at"`
	LastGeoLookupAt        string         `json:"last_geo_lookup_at"`
	SourceNames            []string       `json:"source_names"`
	ActiveSecurityFindings []string       `json:"active_security_findings"`
	Details                map[string]any `json:"details"`
}

type ParsedProxy struct {
	Protocol string
	Raw      string
	Host     string
	Port     int
	Remarks  string
	Details  map[string]any
}

type jsonConfigDetection struct {
	engine        string
	node          map[string]any
	protocol      string
	direction     string
	inboundTypes  []string
	outboundTypes []string
	tag           string
}

type GeoInfo struct {
	Country     string
	CountryCode string
	State       string
	Flag        string
	IP          string
}

type mmdbGeoRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

type mmdbGeoCityRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
}

type Logger struct {
	cfg Config
	ui  *LiveUI
}

type LiveUI struct {
	mu               sync.Mutex
	appStartedAt     time.Time
	interactive      bool
	started          bool
	cycleStartedAt   time.Time
	phase            string
	currentSource    string
	currentTest      string
	currentActivity  string
	sourceIndex      int
	sourceTotal      int
	testIndex        int
	testTotal        int
	totalRecords     int
	pingedRecords    int
	securedRecords   int
	rejectedRecords  int
	unsupported      int
	testsDone        int
	testsOK          int
	testsFailed      int
	testsRejected    int
	testsSkipped     int
	testsUnsupported int
	tcpPrecheckDone  int
	tcpPrecheckTotal int
	tcpPrecheckOK    int
	tcpPrecheckFail  int
	lastSourceCheck  string
	lastGitHubSync   string
	waitLabel        string
	waitUntil        time.Time
	recentLogs       []string
	nextSourceAt     time.Time
	pendingTests     int
	paused           bool
	controlHint      string
	stop             chan struct{}
	done             chan struct{}
}

type RuntimeController struct {
	mu            sync.Mutex
	paused        bool
	stopRequested bool
	forceRefresh  bool
	healthCheck   bool
}

type StateSnapshot struct {
	Total            int
	Pinged           int
	SecurityTested   int
	Rejected         int
	Unsupported      int
	SourceConfigured int
}

type HealthCheckItem struct {
	Section string
	Name    string
	OK      bool
	Detail  string
}

type GitHubRelease struct {
	TagName string               `json:"tag_name"`
	Assets  []GitHubReleaseAsset `json:"assets"`
}

type GitHubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func main() {
	command := "once"
	if len(os.Args) > 1 {
		command = strings.ToLower(strings.TrimSpace(os.Args[1]))
	} else if shouldUseInteractiveMenu() {
		command = "menu"
	}
	if command == "menu" && !isInteractiveTerminal() {
		command = "once"
	}

	cfg, migrated, err := loadConfig(defaultConfigFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	if err := ensureRuntimePaths(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "path error: %v\n", err)
		os.Exit(1)
	}

	state, err := loadState(cfg.Paths.StateFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "state error: %v\n", err)
		os.Exit(1)
	}

	if command == "menu" {
		statusMessage := "Ready."
		if migrated {
			statusMessage = "Legacy sources.json/server.json migrated into config.json."
		}
		for {
			currentCfg, _, cfgErr := loadConfig(defaultConfigFile)
			if cfgErr == nil {
				cfg = currentCfg
			}
			currentState, loadErr := loadState(cfg.Paths.StateFile)
			if loadErr == nil {
				state = currentState
			}
			choice, promptErr := promptInteractiveCommand(cfg, state, statusMessage)
			if promptErr != nil {
				fmt.Fprintf(os.Stderr, "menu error: %v\n", promptErr)
				os.Exit(1)
			}
			if choice == "exit" {
				return
			}
			result, execErr := executeCommand(choice, cfg, state)
			if execErr != nil {
				statusMessage = fmt.Sprintf("%s failed: %v", strings.ToUpper(choice), execErr)
				continue
			}
			statusMessage = result
		}
	}

	if migrated {
		fmt.Println("[SCHEDULER] old sources.json/server.json migrated into config.json")
	}
	if _, err := executeCommand(command, cfg, state); err != nil {
		switch command {
		case "telegram-login":
			fmt.Fprintf(os.Stderr, "telegram login error: %v\n", err)
		case "reindex":
			fmt.Fprintf(os.Stderr, "reindex error: %v\n", err)
		case "daemon":
			fmt.Fprintf(os.Stderr, "daemon error: %v\n", err)
		case "check":
			fmt.Fprintf(os.Stderr, "check error: %v\n", err)
		default:
			fmt.Fprintf(os.Stderr, "run error: %v\n", err)
		}
		os.Exit(1)
	}
}

func executeCommand(command string, cfg Config, state *State) (string, error) {
	logger := Logger{cfg: cfg}
	var controller *RuntimeController
	var restoreInput func()
	if command == "daemon" || command == "once" {
		logger.ui = newLiveUI()
		if command == "daemon" {
			restoreInput, controller = setupRuntimeInput(logger.ui)
			if restoreInput != nil {
				defer restoreInput()
			}
		}
		logger.ui.Start()
		defer logger.ui.Stop()
	}

	switch command {
	case "init":
		logger.console("scheduler", "config.json and state paths are ready")
		return "Runtime paths are ready.", nil
	case "check":
		runCheck(cfg, state, logger)
		return "Health check completed.", nil
	case "resources":
		if err := showResourcesScreen(cfg, state); err != nil {
			return "", err
		}
		return "Resources view closed.", nil
	case "settings":
		changed, err := showSettingsScreen(defaultConfigFile, cfg)
		if err != nil {
			return "", err
		}
		if changed {
			return "Settings updated in config.json.", nil
		}
		return "Settings unchanged.", nil
	case "telegram-login":
		if err := ensureTelegramRuntime(cfg, logger); err != nil {
			return "", err
		}
		if err := runTelegramPythonHelperInteractive("--login"); err != nil {
			return "", err
		}
		return "Telegram session refreshed.", nil
	case "reindex":
		if err := writeOutputs(cfg, state, logger); err != nil {
			return "", err
		}
		if cfg.GitHub.Enabled && cfg.GitHub.Token != "" && cfg.GitHub.Repository != "" {
			if err := syncGitHub(cfg, state, logger); err != nil {
				return "", err
			}
			state.LastGitHubSync = time.Now().UTC().Format(time.RFC3339)
		}
		if err := saveState(cfg.Paths.StateFile, state); err != nil {
			return "", err
		}
		return "Category outputs rebuilt from saved state.", nil
	case "daemon":
		runCheck(cfg, state, logger)
		if err := runDaemon(cfg, state, logger, controller); err != nil {
			return "", err
		}
		return "Watch mode stopped.", nil
	default:
		runCheck(cfg, state, logger)
		if err := runCycle(cfg, state, logger, true); err != nil {
			return "", err
		}
		return "Harvest cycle completed.", nil
	}
}

func defaultConfig() Config {
	return Config{
		Sources: []SourceSpec{
			{Name: "sample-subscription-1", Type: "subscription", Enabled: false, Links: []string{"https://example.com/subscription-1.txt"}},
			{Name: "sample-subscription-2", Type: "subscription", Enabled: false, Links: []string{"https://example.com/subscription-2.txt"}},
			{Name: "sample-telegram-1", Type: "telegram", Enabled: false, Channel: "public_channel_one"},
			{Name: "sample-telegram-2", Type: "telegram", Enabled: false, Channel: "public_channel_two"},
		},
		Telegram: TelegramConfig{
			APIID:      0,
			APIHash:    "",
			Session:    "sentinel_session",
			UseWebOnly: true,
		},
		GitHub: GitHubConfig{
			Enabled:          false,
			Token:            "",
			Repository:       "",
			Branch:           "",
			BasePath:         "",
			SyncEveryMinutes: 15,
		},
		Schedule: ScheduleConfig{
			SourceCheckEveryMinutes: 15,
			RetestEveryHours:        24,
		},
		Probes: ProbeConfig{
			TimeoutSeconds:         8,
			EnableTCPPrecheck:      false,
			TCPPrecheckTimeoutMS:   600,
			FallbackProbeURLs:      true,
			UseAllProbeURLs:        false,
			PerConfigTimeoutMS:     1200,
			CoreStartupWaitMS:      250,
			SecurityProbeTimeoutMS: 700,
			EnableProxyGeoLookup:   false,
			PingURLs: []string{
				"https://www.gstatic.com/generate_204",
				"https://cp.cloudflare.com/generate_204",
			},
			SpeedURLs: []string{
				"https://speed.cloudflare.com/__down?bytes=1048576",
			},
			SecurityProbes: []ActiveSecurityProbe{
				{
					Name:           "google-http-204",
					URL:            "http://connectivitycheck.gstatic.com/generate_204",
					Method:         "GET",
					ExpectStatus:   204,
					RejectContains: []string{"<script", "<html", "<!doctype", "window.location", "document.location", "http-equiv", "captcha", "access denied", "fortigate", "mikrotik"},
					ExpectMaxBytes: 0,
					RejectRedirect: true,
					Severity:       "critical",
					CompareGroup:   "portal-204",
					Critical:       true,
					Penalty:        170,
				},
				{
					Name:              "msft-http-connect",
					URL:               "http://www.msftconnecttest.com/connecttest.txt",
					Method:            "GET",
					ExpectStatus:      200,
					ExpectContentType: "text/plain",
					ExpectContains:    []string{"Microsoft Connect Test"},
					RejectContains:    []string{"<script", "<html", "<!doctype", "window.location", "document.location", "http-equiv", "captcha", "access denied", "fortigate", "mikrotik"},
					ExpectMinBytes:    10,
					ExpectMaxBytes:    512,
					RejectRedirect:    true,
					Severity:          "critical",
					CompareGroup:      "plain-http-text",
					Critical:          true,
					Penalty:           170,
				},
				{
					Name:           "google-204",
					URL:            "https://www.gstatic.com/generate_204",
					Method:         "GET",
					ExpectStatus:   204,
					RejectContains: []string{"<script", "<html", "<!doctype", "window.location", "document.location", "http-equiv", "captcha", "access denied", "fortigate", "mikrotik"},
					ExpectMaxBytes: 0,
					RejectRedirect: true,
					Severity:       "critical",
					CompareGroup:   "portal-204",
					Critical:       true,
					Penalty:        120,
				},
				{
					Name:           "cloudflare-204",
					URL:            "https://cp.cloudflare.com/generate_204",
					Method:         "GET",
					ExpectStatus:   204,
					RejectContains: []string{"<script", "<html", "<!doctype", "window.location", "document.location", "http-equiv", "captcha", "access denied", "fortigate", "mikrotik"},
					ExpectMaxBytes: 0,
					RejectRedirect: true,
					Severity:       "critical",
					CompareGroup:   "portal-204",
					Critical:       true,
					Penalty:        120,
				},
				{
					Name:              "cloudflare-trace",
					URL:               "https://www.cloudflare.com/cdn-cgi/trace",
					Method:            "GET",
					Headers:           map[string]string{"Accept": "text/plain"},
					ExpectStatus:      200,
					ExpectContentType: "text/plain",
					ExpectContains:    []string{"ip=", "h="},
					RejectContains:    []string{"<script", "<html", "<!doctype", "window.location", "document.location"},
					ExpectMinBytes:    20,
					ExpectMaxBytes:    4096,
					RejectRedirect:    true,
					MaxRedirects:      1,
					Severity:          "critical",
					CompareGroup:      "trace-text",
					Critical:          true,
					Penalty:           150,
				},
				{
					Name:              "cloudflare-doh",
					URL:               "https://cloudflare-dns.com/dns-query?name=example.com&type=A",
					Method:            "GET",
					Headers:           map[string]string{"Accept": "application/dns-json"},
					ExpectStatus:      200,
					ExpectContentType: "json",
					ExpectContains:    []string{"Status", "Answer"},
					RejectContains:    []string{"<script", "<html", "<!doctype"},
					ExpectMinBytes:    20,
					ExpectMaxBytes:    16384,
					RejectRedirect:    true,
					MaxRedirects:      1,
					Severity:          "critical",
					CompareGroup:      "dns-json",
					Critical:          true,
					Penalty:           140,
				},
				{
					Name:              "google-doh",
					URL:               "https://dns.google/resolve?name=example.com&type=A",
					Method:            "GET",
					ExpectStatus:      200,
					ExpectContentType: "json",
					ExpectContains:    []string{"Status", "Answer"},
					RejectContains:    []string{"<script", "<html", "<!doctype"},
					ExpectMinBytes:    20,
					ExpectMaxBytes:    16384,
					RejectRedirect:    true,
					MaxRedirects:      1,
					Severity:          "critical",
					CompareGroup:      "dns-json",
					Critical:          true,
					Penalty:           140,
				},
			},
			GeoLookupURLs: []string{
				"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,query",
				"https://ipwho.is/{ip}",
			},
			ProxyGeoURLs: []string{
				"http://ip-api.com/json/?fields=status,country,countryCode,regionName,query",
				"https://ipwho.is/",
			},
			ProxyIPURLs: []string{
				"https://www.cloudflare.com/cdn-cgi/trace",
				"https://api.ipify.org?format=json",
				"https://ipv4.icanhazip.com",
			},
			LocalGeoDB:      "GeoLite2-Country.mmdb",
			LocalGeoCityDB:  "GeoLite2-City.mmdb",
			SpeedTestBytes:  1048576,
			FastSpeedMBps:   5,
			MediumSpeedMBps: 1,
		},
		Cores: CoreConfig{
			XrayPath:    defaultCorePath("xray_bin", "xray"),
			SingBoxPath: defaultCorePath("singbox_bin", "sing-box"),
		},
		Logging: LoggingConfig{
			ConsoleVerbose: true,
			Directory:      defaultLogsDir,
			Sections: map[string]SectionLog{
				"source":    {FileEnabled: true},
				"parsing":   {FileEnabled: true},
				"geo":       {FileEnabled: true},
				"testing":   {FileEnabled: true},
				"security":  {FileEnabled: true},
				"telegram":  {FileEnabled: true},
				"github":    {FileEnabled: true},
				"core":      {FileEnabled: true},
				"scheduler": {FileEnabled: true},
			},
		},
		Paths: PathsConfig{
			StateFile:         defaultStateFile,
			ConfigsDir:        "configs",
			CountryDir:        "country",
			ProtocolDir:       "protocol",
			SecurityDir:       "security",
			SpeedDir:          "speed",
			AllScrapedFile:    filepath.Join("configs", "all_scraped.txt"),
			AllWorkingFile:    filepath.Join("configs", "all_working.txt"),
			AllSecureFile:     filepath.Join("configs", "all_secure.txt"),
			AllScrapedDir:     "country",
			SecurityTestDir:   "security",
			AllPingedFile:     filepath.Join("configs", "all_working.txt"),
			AllSecurityTested: filepath.Join("configs", "all_secure.txt"),
		},
	}
}

func defaultCorePath(dir, name string) string {
	file := name
	if runtime.GOOS == "windows" {
		file += ".exe"
	}
	return filepath.Join(dir, file)
}

func loadConfig(path string) (Config, bool, error) {
	cfg := defaultConfig()
	if fileExists(path) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return cfg, false, err
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return cfg, false, err
		}
		fillDefaults(&cfg)
		return cfg, false, nil
	}

	migrated := migrateLegacyConfig(&cfg)
	fillDefaults(&cfg)
	if err := writeJSON(path, cfg); err != nil {
		return cfg, migrated, err
	}
	return cfg, migrated, nil
}

func fillDefaults(cfg *Config) {
	def := defaultConfig()
	if cfg.Schedule.SourceCheckEveryMinutes <= 0 {
		cfg.Schedule.SourceCheckEveryMinutes = def.Schedule.SourceCheckEveryMinutes
	}
	if cfg.Schedule.SourceCheckEveryMinutes < 15 {
		cfg.Schedule.SourceCheckEveryMinutes = 15
	}
	if cfg.Schedule.RetestEveryHours <= 0 {
		cfg.Schedule.RetestEveryHours = def.Schedule.RetestEveryHours
	}
	if cfg.GitHub.SyncEveryMinutes <= 0 {
		cfg.GitHub.SyncEveryMinutes = def.GitHub.SyncEveryMinutes
	}
	if cfg.Probes.TimeoutSeconds <= 0 {
		cfg.Probes.TimeoutSeconds = def.Probes.TimeoutSeconds
	}
	if len(cfg.Probes.PingURLs) == 0 {
		cfg.Probes.PingURLs = def.Probes.PingURLs
	}
	if len(cfg.Probes.SpeedURLs) == 0 {
		cfg.Probes.SpeedURLs = def.Probes.SpeedURLs
	}
	if len(cfg.Probes.SecurityProbes) == 0 {
		cfg.Probes.SecurityProbes = def.Probes.SecurityProbes
	}
	if len(cfg.Probes.GeoLookupURLs) == 0 {
		cfg.Probes.GeoLookupURLs = def.Probes.GeoLookupURLs
	}
	if len(cfg.Probes.ProxyGeoURLs) == 0 {
		cfg.Probes.ProxyGeoURLs = def.Probes.ProxyGeoURLs
	}
	if len(cfg.Probes.ProxyIPURLs) == 0 {
		cfg.Probes.ProxyIPURLs = def.Probes.ProxyIPURLs
	}
	if cfg.Probes.LocalGeoDB == "" {
		cfg.Probes.LocalGeoDB = def.Probes.LocalGeoDB
	}
	if cfg.Probes.LocalGeoCityDB == "" {
		cfg.Probes.LocalGeoCityDB = def.Probes.LocalGeoCityDB
	}
	if cfg.Probes.SpeedTestBytes <= 0 {
		cfg.Probes.SpeedTestBytes = def.Probes.SpeedTestBytes
	}
	if cfg.Probes.FastSpeedMBps <= 0 {
		cfg.Probes.FastSpeedMBps = def.Probes.FastSpeedMBps
	}
	if cfg.Probes.MediumSpeedMBps <= 0 {
		cfg.Probes.MediumSpeedMBps = def.Probes.MediumSpeedMBps
	}
	if cfg.Probes.TCPPrecheckTimeoutMS <= 0 {
		cfg.Probes.TCPPrecheckTimeoutMS = def.Probes.TCPPrecheckTimeoutMS
	}
	if cfg.Probes.PerConfigTimeoutMS <= 0 {
		cfg.Probes.PerConfigTimeoutMS = def.Probes.PerConfigTimeoutMS
	}
	if cfg.Probes.CoreStartupWaitMS <= 0 {
		cfg.Probes.CoreStartupWaitMS = def.Probes.CoreStartupWaitMS
	}
	if cfg.Probes.SecurityProbeTimeoutMS <= 0 {
		cfg.Probes.SecurityProbeTimeoutMS = def.Probes.SecurityProbeTimeoutMS
	}
	if cfg.Paths.StateFile == "" {
		cfg.Paths.StateFile = def.Paths.StateFile
	}
	if cfg.Paths.ConfigsDir == "" {
		cfg.Paths.ConfigsDir = def.Paths.ConfigsDir
	}
	if cfg.Paths.CountryDir == "" {
		cfg.Paths.CountryDir = def.Paths.CountryDir
	}
	if cfg.Paths.ProtocolDir == "" {
		cfg.Paths.ProtocolDir = def.Paths.ProtocolDir
	}
	if cfg.Paths.SecurityDir == "" {
		cfg.Paths.SecurityDir = def.Paths.SecurityDir
	}
	if cfg.Paths.SpeedDir == "" {
		cfg.Paths.SpeedDir = def.Paths.SpeedDir
	}
	if cfg.Paths.AllScrapedFile == "" {
		cfg.Paths.AllScrapedFile = def.Paths.AllScrapedFile
	}
	if cfg.Paths.AllWorkingFile == "" {
		cfg.Paths.AllWorkingFile = def.Paths.AllWorkingFile
	}
	if cfg.Paths.AllSecureFile == "" {
		cfg.Paths.AllSecureFile = def.Paths.AllSecureFile
	}
	if cfg.Paths.AllScrapedDir == "" {
		cfg.Paths.AllScrapedDir = def.Paths.AllScrapedDir
	}
	if cfg.Paths.SecurityTestDir == "" {
		cfg.Paths.SecurityTestDir = def.Paths.SecurityTestDir
	}
	if cfg.Paths.AllPingedFile == "" {
		cfg.Paths.AllPingedFile = def.Paths.AllPingedFile
	}
	if cfg.Paths.AllSecurityTested == "" {
		cfg.Paths.AllSecurityTested = def.Paths.AllSecurityTested
	}
	if cfg.Logging.Directory == "" {
		cfg.Logging.Directory = def.Logging.Directory
	}
	if cfg.Logging.Sections == nil {
		cfg.Logging.Sections = make(map[string]SectionLog, len(def.Logging.Sections))
	}
	for key, value := range def.Logging.Sections {
		if _, ok := cfg.Logging.Sections[key]; !ok {
			cfg.Logging.Sections[key] = value
		}
	}
	if strings.HasSuffix(strings.ToLower(cfg.GitHub.BasePath), ".txt") {
		cfg.GitHub.BasePath = filepath.ToSlash(filepath.Dir(cfg.GitHub.BasePath))
		if cfg.GitHub.BasePath == "." {
			cfg.GitHub.BasePath = ""
		}
	}
	if cfg.Cores.XrayPath == "" {
		cfg.Cores.XrayPath = def.Cores.XrayPath
	}
	if cfg.Cores.SingBoxPath == "" {
		cfg.Cores.SingBoxPath = def.Cores.SingBoxPath
	}
}

func migrateLegacyConfig(cfg *Config) bool {
	type legacySources struct {
		SubscriptionURLs []string `json:"subscriptionUrls"`
		TelegramChannels []string `json:"telegramChannels"`
		GitHubToken      string   `json:"githubToken"`
		GitHubRepo       string   `json:"githubRepo"`
		GitHubPath       string   `json:"githubPath"`
		AutoHarvest      int      `json:"autoHarvestInterval"`
		TelegramAPIID    int      `json:"telegramApiId"`
		TelegramAPIHash  string   `json:"telegramApiHash"`
		Session          string   `json:"telegramSessionName"`
	}
	type legacyServer struct {
		CheckIntervalMinutes        int `json:"checkIntervalMinutes"`
		GitHubUpdateIntervalMinutes int `json:"githubUpdateIntervalMinutes"`
	}

	migrated := false
	if fileExists("sources.json") {
		var old legacySources
		if raw, err := os.ReadFile("sources.json"); err == nil && json.Unmarshal(raw, &old) == nil {
			cfg.Sources = nil
			for idx, link := range old.SubscriptionURLs {
				cfg.Sources = append(cfg.Sources, SourceSpec{Name: fmt.Sprintf("legacy-sub-%d", idx+1), Type: "subscription", Enabled: true, Links: []string{link}})
			}
			for _, channel := range old.TelegramChannels {
				cfg.Sources = append(cfg.Sources, SourceSpec{Name: "telegram-" + sanitizeName(channel), Type: "telegram", Enabled: true, Channel: channel})
			}
			cfg.GitHub.Token = old.GitHubToken
			cfg.GitHub.Repository = old.GitHubRepo
			cfg.GitHub.Enabled = old.GitHubToken != "" && old.GitHubRepo != ""
			cfg.GitHub.BasePath = filepath.ToSlash(filepath.Dir(strings.TrimSpace(old.GitHubPath)))
			if cfg.GitHub.BasePath == "." {
				cfg.GitHub.BasePath = ""
			}
			if old.AutoHarvest > 0 {
				cfg.Schedule.SourceCheckEveryMinutes = old.AutoHarvest
			}
			cfg.Telegram.APIID = old.TelegramAPIID
			cfg.Telegram.APIHash = old.TelegramAPIHash
			if old.Session != "" {
				cfg.Telegram.Session = old.Session
			}
			migrated = true
		}
	}
	if fileExists("server.json") {
		var old legacyServer
		if raw, err := os.ReadFile("server.json"); err == nil && json.Unmarshal(raw, &old) == nil {
			if old.CheckIntervalMinutes > 0 {
				cfg.Schedule.SourceCheckEveryMinutes = old.CheckIntervalMinutes
			}
			if old.GitHubUpdateIntervalMinutes > 0 {
				cfg.GitHub.SyncEveryMinutes = old.GitHubUpdateIntervalMinutes
			}
			migrated = true
		}
	}
	return migrated
}

func ensureRuntimePaths(cfg Config) error {
	dirs := []string{
		filepath.Dir(cfg.Paths.StateFile),
		cfg.Logging.Directory,
		cfg.Paths.ConfigsDir,
		cfg.Paths.CountryDir,
		cfg.Paths.ProtocolDir,
		cfg.Paths.SecurityDir,
		cfg.Paths.SpeedDir,
	}
	for _, dir := range dirs {
		if dir == "." || dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func loadState(path string) (*State, error) {
	if !fileExists(path) {
		state := &State{
			Sources: make(map[string]SourceState),
			Records: make(map[string]*Record),
		}
		return state, saveState(path, state)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	state := &State{}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, err
	}
	if state.Sources == nil {
		state.Sources = make(map[string]SourceState)
	}
	if state.Records == nil {
		state.Records = make(map[string]*Record)
	}
	return state, nil
}

func saveState(path string, state *State) error {
	return writeJSON(path, state)
}

func snapshotState(cfg Config, state *State) StateSnapshot {
	snapshot := StateSnapshot{
		Total:            len(state.Records),
		SourceConfigured: len(cfg.Sources),
	}
	for _, rec := range state.Records {
		if rec.PingOK {
			snapshot.Pinged++
		}
		if rec.Rejected {
			snapshot.Rejected++
		}
		if rec.Unsupported {
			snapshot.Unsupported++
		}
		if rec.PingOK && rec.SecurityLevel != "" && rec.SecurityLevel != "unknown" && rec.SecurityLevel != "rejected" && !strings.EqualFold(rec.SecurityLevel, "risk") {
			snapshot.SecurityTested++
		}
	}
	return snapshot
}

func newLiveUI() *LiveUI {
	return &LiveUI{
		appStartedAt: time.Now(),
		phase:        "startup",
		controlHint:  "P pause/resume  R refresh sources  C health  Q stop",
		recentLogs:   make([]string, 0, 12),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
}

func (ui *LiveUI) Start() {
	if ui == nil || ui.started {
		return
	}
	ui.interactive = prepareConsolePlatform()
	if !ui.interactive {
		return
	}
	ui.started = true
	fmt.Print("\x1b[?1049h\x1b[?25l")
	go func() {
		ticker := time.NewTicker(180 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ui.stop:
				fmt.Print("\x1b[?25h\x1b[0m\x1b[?1049l")
				close(ui.done)
				return
			case <-ticker.C:
				ui.render()
			}
		}
	}()
}

func (ui *LiveUI) Stop() {
	if ui == nil || !ui.started {
		return
	}
	close(ui.stop)
	<-ui.done
}

func (ui *LiveUI) Active() bool {
	return ui != nil && ui.started && ui.interactive
}

func (ui *LiveUI) render() {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	var b strings.Builder
	now := time.Now()
	b.WriteString("\x1b[?25l\x1b[H\x1b[2J")
	b.WriteString(colorize("1;36", "╔══════════════════════════════════════════════════════════════════════════════╗"))
	b.WriteByte('\n')
	header := fmt.Sprintf("║ ProxyHarvest CLI %s  Phase: %s  Uptime: %s", spinnerFrame(now), phaseBadge(ui.phase), formatDurationShort(now.Sub(ui.appStartedAt)))
	b.WriteString(padRightANSI(header, 79) + colorize("1;36", "║"))
	b.WriteByte('\n')
	b.WriteString(colorize("1;36", "╠══════════════════════════════════════════════════════════════════════════════╣"))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("Cycle Started   %s", renderTimeValue(ui.cycleStartedAt))))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("Last Source     %s", fallback(ui.lastSourceCheck, "never"))))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("Last GitHub     %s", fallback(ui.lastGitHubSync, "never"))))
	b.WriteByte('\n')
	queueLine := fmt.Sprintf("Queue      pending:%d  next source:%s  tester:%s", ui.pendingTests, renderTimeValueShort(ui.nextSourceAt), ternaryString(ui.paused, "paused", "running"))
	b.WriteString(wrapBoxLine(queueLine))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(trimForDisplay(ui.controlHint, 66)))
	b.WriteByte('\n')
	b.WriteString(colorize("1;36", "╠══════════════════════════════════════════════════════════════════════════════╣"))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("Sources   %s %3d/%-3d  %s", progressBar(ui.sourceIndex, ui.sourceTotal, 22, "36"), ui.sourceIndex, ui.sourceTotal, trimForDisplay(fallback(ui.currentSource, "-"), 28))))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("Tests     %s %3d/%-3d  %s", progressBar(ui.testIndex, ui.testTotal, 22, "32"), ui.testIndex, ui.testTotal, trimForDisplay(fallback(ui.currentTest, "-"), 28))))
	b.WriteByte('\n')
	testStatsLine := fmt.Sprintf("Status    %s  %s  %s  %s  %s  %s",
		statBadge("DONE", ui.testsDone, "37"),
		statBadge("OK", ui.testsOK, "32"),
		statBadge("FAIL", ui.testsFailed, "31"),
		statBadge("REJ", ui.testsRejected, "35"),
		statBadge("SKIP", ui.testsSkipped, "33"),
		statBadge("UNSUP", ui.testsUnsupported, "34"),
	)
	b.WriteString(wrapBoxLine(testStatsLine))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(fmt.Sprintf("TCP Ping  %s %3d/%-3d  %s  %s",
		progressBar(ui.tcpPrecheckDone, ui.tcpPrecheckTotal, 22, "36"),
		ui.tcpPrecheckDone,
		ui.tcpPrecheckTotal,
		statBadge("TCP_OK", ui.tcpPrecheckOK, "36"),
		statBadge("TCP_FAIL", ui.tcpPrecheckFail, "31"),
	)))
	b.WriteByte('\n')
	statsLine := fmt.Sprintf("Records   %s  %s  %s  %s  %s",
		statBadge("TOTAL", ui.totalRecords, "37"),
		statBadge("PING", ui.pingedRecords, "32"),
		statBadge("SAFE", ui.securedRecords, "36"),
		statBadge("REJ", ui.rejectedRecords, "31"),
		statBadge("UNSUP", ui.unsupported, "33"),
	)
	b.WriteString(wrapBoxLine(statsLine))
	b.WriteByte('\n')
	if !ui.waitUntil.IsZero() {
		remaining := time.Until(ui.waitUntil)
		if remaining < 0 {
			remaining = 0
		}
		b.WriteString(wrapBoxLine(fmt.Sprintf("Wait      %s  %s", trimForDisplay(fallback(ui.waitLabel, "next cycle"), 42), colorize("1;33", remaining.Round(time.Second).String()))))
	} else {
		b.WriteString(wrapBoxLine(fmt.Sprintf("Activity  %s", trimForDisplay(fallback(ui.currentActivity, "-"), 58))))
	}
	b.WriteByte('\n')
	b.WriteString(colorize("1;36", "╠══════════════════════════════════════════════════════════════════════════════╣"))
	b.WriteByte('\n')
	b.WriteString(wrapBoxLine(colorize("1;35", "Recent Logs")))
	b.WriteByte('\n')
	for _, line := range ui.recentLogs {
		b.WriteString(wrapBoxLine(trimForDisplay(line, 66)))
		b.WriteByte('\n')
	}
	for i := len(ui.recentLogs); i < 12; i++ {
		b.WriteString(wrapBoxLine(colorize("2;37", "…")))
		b.WriteByte('\n')
	}
	b.WriteString(colorize("1;36", "╚══════════════════════════════════════════════════════════════════════════════╝"))
	fmt.Print(b.String())
}

func renderTimeValue(value time.Time) string {
	if value.IsZero() {
		return "not-started"
	}
	return value.Format(time.RFC3339)
}

func renderTimeValueShort(value time.Time) string {
	if value.IsZero() {
		return "pending"
	}
	return value.Format("15:04:05")
}

func spinnerFrame(now time.Time) string {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	return colorize("1;36", frames[(now.UnixNano()/int64(140*time.Millisecond))%int64(len(frames))])
}

func phaseBadge(phase string) string {
	phase = strings.TrimSpace(phase)
	if phase == "" {
		phase = "idle"
	}
	color := "1;37"
	switch {
	case strings.Contains(phase, "collect"):
		color = "1;36"
	case strings.Contains(phase, "test"):
		color = "1;32"
	case strings.Contains(phase, "sync"):
		color = "1;35"
	case strings.Contains(phase, "wait"), strings.Contains(phase, "idle"):
		color = "1;33"
	case strings.Contains(phase, "core"):
		color = "1;34"
	}
	return colorize(color, "["+strings.ToUpper(strings.ReplaceAll(phase, "-", " "))+"]")
}

func colorize(code, text string) string {
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func trimForDisplay(text string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(strings.TrimSpace(text))
	if len(runes) <= max {
		return string(runes)
	}
	if max <= 1 {
		return string(runes[:max])
	}
	return string(runes[:max-1]) + "…"
}

func progressBar(current, total, width int, color string) string {
	if width < 8 {
		width = 8
	}
	if total <= 0 {
		total = 1
	}
	if current < 0 {
		current = 0
	}
	if current > total {
		current = total
	}
	filled := int(math.Round((float64(current) / float64(total)) * float64(width)))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return colorize(color, bar)
}

func statBadge(label string, value int, color string) string {
	return colorize(color, fmt.Sprintf("%s:%d", label, value))
}

func wrapBoxLine(content string) string {
	return colorize("1;36", "║ ") + padRightANSI(content, 76) + colorize("1;36", " ║")
}

func padRightANSI(content string, width int) string {
	visible := ansiVisibleLength(content)
	if visible >= width {
		return content
	}
	return content + strings.Repeat(" ", width-visible)
}

func ansiVisibleLength(content string) int {
	length := 0
	inEscape := false
	for _, r := range content {
		switch {
		case r == '\x1b':
			inEscape = true
		case inEscape && r == 'm':
			inEscape = false
		case !inEscape:
			length++
		}
	}
	return length
}

func formatDurationShort(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	s := int((d % time.Minute) / time.Second)
	if h > 0 {
		return fmt.Sprintf("%dh %02dm %02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func (ui *LiveUI) SetPhase(phase, activity string) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.phase = phase
	ui.currentActivity = activity
}

func (ui *LiveUI) SetCycleStart(startedAt time.Time) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.cycleStartedAt = startedAt
	ui.sourceIndex = 0
	ui.sourceTotal = 0
	ui.testIndex = 0
	ui.testTotal = 0
	ui.currentSource = ""
	ui.currentTest = ""
	ui.testsDone = 0
	ui.testsOK = 0
	ui.testsFailed = 0
	ui.testsRejected = 0
	ui.testsSkipped = 0
	ui.testsUnsupported = 0
	ui.tcpPrecheckDone = 0
	ui.tcpPrecheckTotal = 0
	ui.tcpPrecheckOK = 0
	ui.tcpPrecheckFail = 0
	ui.waitUntil = time.Time{}
	ui.waitLabel = ""
}

func (ui *LiveUI) SetSourceProgress(index, total int, current string) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.sourceIndex = index
	ui.sourceTotal = total
	ui.currentSource = current
}

func (ui *LiveUI) SetTestProgress(index, total int, current string) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.testIndex = index
	ui.testTotal = total
	ui.currentTest = current
}

func (ui *LiveUI) SetSnapshot(snapshot StateSnapshot) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.totalRecords = snapshot.Total
	ui.pingedRecords = snapshot.Pinged
	ui.securedRecords = snapshot.SecurityTested
	ui.rejectedRecords = snapshot.Rejected
	ui.unsupported = snapshot.Unsupported
}

func (ui *LiveUI) SetTestCounters(done, ok, failed, rejected, skipped, unsupported int) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.testsDone = done
	ui.testsOK = ok
	ui.testsFailed = failed
	ui.testsRejected = rejected
	ui.testsSkipped = skipped
	ui.testsUnsupported = unsupported
}

func (ui *LiveUI) SetTCPPrecheckCounters(ok, failed int) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.tcpPrecheckOK = ok
	ui.tcpPrecheckFail = failed
}

func (ui *LiveUI) SetTCPPrecheckProgress(done, total int) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.tcpPrecheckDone = done
	ui.tcpPrecheckTotal = total
}

func (ui *LiveUI) SetSyncInfo(lastSource, lastGitHub string) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.lastSourceCheck = lastSource
	ui.lastGitHubSync = lastGitHub
}

func (ui *LiveUI) SetWait(label string, until time.Time) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.phase = "waiting"
	ui.currentActivity = label
	ui.waitLabel = label
	ui.waitUntil = until
}

func (ui *LiveUI) SetRuntimeState(pending int, nextSourceAt time.Time, paused bool) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.pendingTests = pending
	ui.nextSourceAt = nextSourceAt
	ui.paused = paused
}

func (ui *LiveUI) ClearWait() {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.waitLabel = ""
	ui.waitUntil = time.Time{}
	if ui.phase == "waiting" {
		ui.phase = "idle"
	}
}

func (ui *LiveUI) Log(section, line string) {
	if ui == nil {
		return
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	entry := fmt.Sprintf("[%s] %s", strings.ToUpper(section), line)
	ui.recentLogs = append(ui.recentLogs, entry)
	if len(ui.recentLogs) > 12 {
		ui.recentLogs = ui.recentLogs[len(ui.recentLogs)-12:]
	}
	ui.currentActivity = line
}

func waitWithSpinner(duration time.Duration, label string, ui *LiveUI) {
	if duration <= 0 {
		return
	}
	if ui != nil && ui.Active() {
		ui.SetWait(label, time.Now().Add(duration))
		time.Sleep(duration)
		ui.ClearWait()
		return
	}
	frames := []string{"|", "/", "-", "\\"}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.Now().Add(duration)
	index := 0
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			fmt.Printf("\r[WAIT] %s ... done%*s\n", label, 20, "")
			return
		}
		fmt.Printf("\r[WAIT] %s ... %s %s", label, frames[index%len(frames)], remaining.Round(time.Second))
		index++
		<-ticker.C
	}
}

func runHealthChecks(cfg Config, logger Logger) []HealthCheckItem {
	client := newHTTPClient(cfg.Probes.TimeoutSeconds, nil)
	items := make([]HealthCheckItem, 0, 8)
	items = append(items, HealthCheckItem{
		Section: "core",
		Name:    "xray",
		OK:      fileExists(cfg.Cores.XrayPath),
		Detail:  cfg.Cores.XrayPath,
	})
	items = append(items, HealthCheckItem{
		Section: "core",
		Name:    "sing-box",
		OK:      fileExists(cfg.Cores.SingBoxPath),
		Detail:  cfg.Cores.SingBoxPath,
	})
	if url := firstNonEmptyURL(cfg.Probes.PingURLs...); url != "" {
		ok, detail := quickCheckURL(client, url, http.MethodGet)
		items = append(items, HealthCheckItem{Section: "scheduler", Name: "ping-url", OK: ok, Detail: detail})
	}
	if url := firstNonEmptyURL(cfg.Probes.SpeedURLs...); url != "" {
		ok, detail := quickCheckURL(client, url, http.MethodHead)
		items = append(items, HealthCheckItem{Section: "scheduler", Name: "speed-url", OK: ok, Detail: detail})
	}
	if url := firstNonEmptyURL(cfg.Probes.ProxyIPURLs...); url != "" {
		ok, detail := quickCheckURL(client, url, http.MethodGet)
		items = append(items, HealthCheckItem{Section: "geo", Name: "proxy-ip", OK: ok, Detail: detail})
	}
	if url := firstNonEmptyURL(cfg.Probes.GeoLookupURLs...); url != "" {
		ok, detail := quickCheckURL(client, strings.ReplaceAll(url, "{ip}", "1.1.1.1"), http.MethodGet)
		items = append(items, HealthCheckItem{Section: "geo", Name: "geo-api", OK: ok, Detail: detail})
	}
	items = append(items, HealthCheckItem{
		Section: "geo",
		Name:    "country-db",
		OK:      fileExists(cfg.Probes.LocalGeoDB),
		Detail:  cfg.Probes.LocalGeoDB,
	})
	if strings.TrimSpace(cfg.Probes.LocalGeoCityDB) != "" {
		items = append(items, HealthCheckItem{
			Section: "geo",
			Name:    "city-db",
			OK:      fileExists(cfg.Probes.LocalGeoCityDB),
			Detail:  cfg.Probes.LocalGeoCityDB,
		})
	}
	if cfg.GitHub.Enabled && cfg.GitHub.Repository != "" && cfg.GitHub.Token != "" {
		ok, detail := quickCheckGitHub(client, cfg.GitHub)
		items = append(items, HealthCheckItem{Section: "github", Name: "api", OK: ok, Detail: detail})
	}
	for _, source := range cfg.Sources {
		if !source.Enabled || !strings.EqualFold(source.Type, "telegram") {
			continue
		}
		target := "https://t.me/s/" + source.Channel
		tgClient := newHTTPClient(maxInt(cfg.Probes.TimeoutSeconds, 18), nil)
		ok, detail := quickCheckTelegramWeb(tgClient, target)
		items = append(items, HealthCheckItem{Section: "telegram", Name: "web", OK: ok, Detail: trimForDisplay(detail, 54)})
		apiOK, apiDetail := telegramAuthHealth(cfg, source.Channel)
		items = append(items, HealthCheckItem{Section: "telegram", Name: "api", OK: apiOK, Detail: trimForDisplay(apiDetail, 54)})
		items = append(items, HealthCheckItem{
			Section: "telegram",
			Name:    "session",
			OK:      fileExists(telegramSessionFile(cfg)),
			Detail:  telegramSessionFile(cfg),
		})
		break
	}
	for _, source := range cfg.Sources {
		if !source.Enabled {
			continue
		}
		target := ""
		switch strings.ToLower(source.Type) {
		case "telegram":
			if source.Channel != "" {
				target = "https://t.me/s/" + source.Channel
			}
		default:
			target = firstNonEmptyURL(source.Links...)
		}
		if target == "" {
			continue
		}
		ok, detail := quickCheckURL(client, target, http.MethodGet)
		items = append(items, HealthCheckItem{Section: "source", Name: source.Name, OK: ok, Detail: detail})
		if len(items) >= 10 {
			break
		}
	}
	logger.file("scheduler", "health checks completed items=%d", len(items))
	return items
}

func firstNonEmptyURL(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func quickCheckURL(client *http.Client, rawURL, method string) (bool, string) {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("User-Agent", "proxyharvest-cli/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 256))
	return resp.StatusCode >= 200 && resp.StatusCode < 500, fmt.Sprintf("%s %s", resp.Status, rawURL)
}

func quickCheckTelegramWeb(client *http.Client, rawURL string) (bool, string) {
	body, err := httpGetTelegramWebBody(client, rawURL)
	if err != nil {
		return false, err.Error()
	}
	return strings.TrimSpace(body) != "", "ok " + rawURL
}

func quickCheckGitHub(client *http.Client, cfg GitHubConfig) (bool, string) {
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/"+strings.Trim(cfg.Repository, "/"), nil)
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("User-Agent", "proxyharvest-cli/1.0")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 256))
	return resp.StatusCode >= 200 && resp.StatusCode < 300, resp.Status
}

func getPythonCommand() (string, []string, error) {
	candidates := []struct {
		bin  string
		args []string
	}{
		{bin: "python", args: nil},
		{bin: "python3", args: nil},
		{bin: "py", args: []string{"-3"}},
	}
	for _, candidate := range candidates {
		if _, err := exec.LookPath(candidate.bin); err == nil {
			return candidate.bin, candidate.args, nil
		}
	}
	return "", nil, errors.New("python runtime not found")
}

func runTelegramPythonHelper(args ...string) (string, error) {
	pythonBin, pythonArgs, err := getPythonCommand()
	if err != nil {
		return "", err
	}
	cmdArgs := append(append([]string{}, pythonArgs...), "telegram_auth_helper.py")
	cmdArgs = append(cmdArgs, args...)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, pythonBin, cmdArgs...)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return strings.TrimSpace(string(output)), errors.New("telegram helper timed out")
	}
	return strings.TrimSpace(string(output)), err
}

func runTelegramPythonHelperInteractive(args ...string) error {
	pythonBin, pythonArgs, err := getPythonCommand()
	if err != nil {
		return err
	}
	cmdArgs := append(append([]string{}, pythonArgs...), "telegram_auth_helper.py")
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command(pythonBin, cmdArgs...)
	cmd.Dir = "."
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func telegramSessionFile(cfg Config) string {
	name := strings.TrimSpace(cfg.Telegram.Session)
	if name == "" {
		name = "sentinel_session"
	}
	if !strings.HasSuffix(strings.ToLower(name), ".session") {
		name += ".session"
	}
	return name
}

func hasEnabledTelegramSource(cfg Config) bool {
	for _, source := range cfg.Sources {
		if source.Enabled && strings.EqualFold(source.Type, "telegram") {
			return true
		}
	}
	return false
}

func telegramAPIConfigured(cfg Config) bool {
	return cfg.Telegram.APIID > 0 && strings.TrimSpace(cfg.Telegram.APIHash) != ""
}

func ensurePythonPackage(moduleName, importName string, logger Logger) error {
	pythonBin, pythonArgs, err := getPythonCommand()
	if err != nil {
		return err
	}
	checkArgs := append(append([]string{}, pythonArgs...), "-c", "import "+importName)
	checkCmd := exec.Command(pythonBin, checkArgs...)
	checkCmd.Dir = "."
	if err := checkCmd.Run(); err == nil {
		return nil
	}
	logger.console("telegram", "installing python package %s", moduleName)
	logger.file("telegram", "installing python package %s", moduleName)
	installArgs := append(append([]string{}, pythonArgs...), "-m", "pip", "install", "--disable-pip-version-check", "--upgrade", moduleName)
	installCmd := exec.Command(pythonBin, installArgs...)
	installCmd.Dir = "."
	output, err := installCmd.CombinedOutput()
	if err != nil {
		message := trimForDisplay(strings.TrimSpace(string(output)), 180)
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("pip install %s failed: %s", moduleName, message)
	}
	return nil
}

func ensureTelegramRuntime(cfg Config, logger Logger) error {
	if !hasEnabledTelegramSource(cfg) || !telegramAPIConfigured(cfg) {
		return nil
	}
	if err := ensurePythonPackage("telethon", "telethon", logger); err != nil {
		return err
	}
	return nil
}

func telegramAuthHealth(cfg Config, channel string) (bool, string) {
	if !telegramAPIConfigured(cfg) {
		return false, "telegram api config missing"
	}
	output, err := runTelegramPythonHelper("--health", channel)
	if err != nil && strings.TrimSpace(output) == "" {
		return false, err.Error()
	}
	var payload map[string]any
	if json.Unmarshal([]byte(output), &payload) == nil {
		ok := strings.EqualFold(asString(payload["ok"]), "true") || payload["ok"] == true
		detail := firstNonEmpty(asString(payload["detail"]), output)
		if !ok && strings.Contains(strings.ToLower(detail), "not-authorized") {
			detail = detail + " (run proxyharvest.exe telegram-login)"
		}
		return ok, detail
	}
	if err != nil {
		return false, firstNonEmpty(output, err.Error())
	}
	return true, firstNonEmpty(output, "telegram api helper ok")
}

func telegramDumpViaAPI(cfg Config, channel string, limit int) ([]string, error) {
	if !telegramAPIConfigured(cfg) {
		return nil, errors.New("telegram api config missing")
	}
	output, err := runTelegramPythonHelper("--dump", channel, "--limit", strconv.Itoa(limit))
	if err != nil && strings.TrimSpace(output) == "" {
		return nil, err
	}
	if strings.HasPrefix(strings.TrimSpace(output), "{") {
		return nil, errors.New(output)
	}
	lines := strings.Split(output, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	if len(result) == 0 && err != nil {
		return nil, err
	}
	return dedupeStrings(result), nil
}

func ensureCoreBinaries(cfg Config, logger Logger) error {
	errs := make([]string, 0, 2)
	if err := ensureCoreBinary("xray", "XTLS/Xray-core", cfg.Cores.XrayPath, cfg.Probes.TimeoutSeconds, logger); err != nil {
		errs = append(errs, err.Error())
	}
	if err := ensureCoreBinary("sing-box", "SagerNet/sing-box", cfg.Cores.SingBoxPath, cfg.Probes.TimeoutSeconds, logger); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func ensureCoreBinary(name, repo, destPath string, timeoutSeconds int, logger Logger) error {
	if fileExists(destPath) {
		logger.file("core", "%s already present: %s", name, destPath)
		return nil
	}
	logger.console("core", "%s missing, downloading from official %s release", name, repo)
	logger.file("core", "%s missing, downloading from official %s release", name, repo)
	asset, tag, err := fetchLatestCoreAsset(repo, timeoutSeconds)
	if err != nil {
		return fmt.Errorf("%s download metadata failed: %w", name, err)
	}
	logger.console("core", "%s release=%s asset=%s", name, tag, asset.Name)
	tmpDir, err := os.MkdirTemp("", "proxyharvest-core-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	waitLabel := fmt.Sprintf("downloading %s", name)
	done := make(chan struct{})
	go spinUntilDone(done, waitLabel, logger.ui)
	binaryPath, err := downloadAndExtractCoreAsset(asset, destPath, timeoutSeconds, tmpDir)
	close(done)
	if err != nil {
		return fmt.Errorf("%s download failed: %w", name, err)
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(destPath, content, 0o755); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(destPath, 0o755)
	}
	logger.console("core", "%s ready at %s", name, destPath)
	logger.file("core", "%s ready at %s", name, destPath)
	return nil
}

func spinUntilDone(done <-chan struct{}, label string, ui *LiveUI) {
	if ui != nil {
		ui.SetPhase("core-bootstrap", label)
		<-done
		return
	}
	frames := []string{"|", "/", "-", "\\"}
	ticker := time.NewTicker(180 * time.Millisecond)
	defer ticker.Stop()
	index := 0
	for {
		select {
		case <-done:
			fmt.Printf("\r[WAIT] %s ... done%*s\n", label, 20, "")
			return
		case <-ticker.C:
			fmt.Printf("\r[WAIT] %s ... %s", label, frames[index%len(frames)])
			index++
		}
	}
}

func fetchLatestCoreAsset(repo string, timeoutSeconds int) (GitHubReleaseAsset, string, error) {
	client := newHTTPClient(timeoutSeconds, nil)
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return GitHubReleaseAsset{}, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "proxyharvest-cli/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return GitHubReleaseAsset{}, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return GitHubReleaseAsset{}, "", fmt.Errorf("release api %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return GitHubReleaseAsset{}, "", err
	}
	asset, err := selectCoreAsset(repo, release.Assets)
	return asset, release.TagName, err
}

func selectCoreAsset(repo string, assets []GitHubReleaseAsset) (GitHubReleaseAsset, error) {
	osTokens := map[string][]string{
		"windows": {"windows"},
		"linux":   {"linux"},
		"darwin":  {"darwin", "macos"},
	}
	archTokens := map[string][]string{
		"amd64": {"amd64", "x64", "x86_64", "64"},
		"arm64": {"arm64", "aarch64", "armv8"},
		"386":   {"386", "32", "x86"},
		"arm":   {"armv7", "arm32", "arm"},
	}
	extAllowed := []string{".zip", ".tar.gz"}
	for _, asset := range assets {
		name := strings.ToLower(asset.Name)
		if strings.HasSuffix(name, ".dgst") || strings.HasSuffix(name, ".sig") || strings.HasSuffix(name, ".sha256sum") {
			continue
		}
		if !containsAny(name, osTokens[runtime.GOOS]) {
			continue
		}
		if !assetMatchesArch(name, runtime.GOARCH, archTokens) {
			continue
		}
		if !hasAnySuffix(name, extAllowed) {
			continue
		}
		if strings.Contains(strings.ToLower(repo), "xray") && !strings.Contains(name, "xray") {
			continue
		}
		if strings.Contains(strings.ToLower(repo), "sing-box") && !strings.Contains(name, "sing-box") {
			continue
		}
		return asset, nil
	}
	return GitHubReleaseAsset{}, fmt.Errorf("no release asset for %s/%s", runtime.GOOS, runtime.GOARCH)
}

func assetMatchesArch(name, arch string, tokens map[string][]string) bool {
	switch arch {
	case "amd64":
		if containsAny(name, []string{"arm64", "armv8", "aarch64"}) {
			return false
		}
	case "386":
		if strings.Contains(name, "64") {
			return false
		}
	case "arm":
		if containsAny(name, []string{"arm64", "armv8", "aarch64"}) {
			return false
		}
	}
	return containsAny(name, tokens[arch])
}

func downloadAndExtractCoreAsset(asset GitHubReleaseAsset, destPath string, timeoutSeconds int, tmpDir string) (string, error) {
	client := newHTTPClient(timeoutSeconds, nil)
	req, err := http.NewRequest(http.MethodGet, asset.BrowserDownloadURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "proxyharvest-cli/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("download %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	archivePath := filepath.Join(tmpDir, asset.Name)
	out, err := os.Create(archivePath)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	targetBinary := filepath.Base(destPath)
	switch {
	case strings.HasSuffix(strings.ToLower(asset.Name), ".zip"):
		return extractBinaryFromZip(archivePath, tmpDir, targetBinary)
	case strings.HasSuffix(strings.ToLower(asset.Name), ".tar.gz"):
		return extractBinaryFromTarGz(archivePath, tmpDir, targetBinary)
	default:
		return "", fmt.Errorf("unsupported archive format: %s", asset.Name)
	}
}

func extractBinaryFromZip(archivePath, tmpDir, targetBinary string) (string, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer reader.Close()
	for _, file := range reader.File {
		if !strings.EqualFold(filepath.Base(file.Name), targetBinary) {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return "", err
		}
		defer rc.Close()
		target := filepath.Join(tmpDir, targetBinary)
		out, err := os.Create(target)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			return "", err
		}
		if err := out.Close(); err != nil {
			return "", err
		}
		return target, nil
	}
	return "", errors.New("binary not found in zip archive")
}

func extractBinaryFromTarGz(archivePath, tmpDir, targetBinary string) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if !strings.EqualFold(filepath.Base(header.Name), targetBinary) {
			continue
		}
		target := filepath.Join(tmpDir, targetBinary)
		out, err := os.Create(target)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, tarReader); err != nil {
			out.Close()
			return "", err
		}
		if err := out.Close(); err != nil {
			return "", err
		}
		return target, nil
	}
	return "", errors.New("binary not found in tar.gz archive")
}

func containsAny(value string, needles []string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(value, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func hasAnySuffix(value string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(value, strings.ToLower(suffix)) {
			return true
		}
	}
	return false
}

func runCheck(cfg Config, state *State, logger Logger) {
	if logger.ui != nil {
		logger.ui.SetPhase("startup-check", "running startup checks")
		logger.ui.SetSnapshot(snapshotState(cfg, state))
		logger.ui.SetSyncInfo(fallback(state.LastSourceCheck, "never"), fallback(state.LastGitHubSync, "never"))
	}
	logger.console("scheduler", "config=%s state=%s", defaultConfigFile, cfg.Paths.StateFile)
	logger.console("scheduler", "timing source_check=%dm retest=%dh github_sync=%dm", cfg.Schedule.SourceCheckEveryMinutes, cfg.Schedule.RetestEveryHours, cfg.GitHub.SyncEveryMinutes)
	logger.console("scheduler", "daemon refreshes sources every %dm while the test queue stays active", cfg.Schedule.SourceCheckEveryMinutes)
	logger.console("scheduler", "last_source_check=%s last_github_sync=%s", fallback(state.LastSourceCheck, "never"), fallback(state.LastGitHubSync, "never"))
	snapshot := snapshotState(cfg, state)
	logger.console("scheduler", "records total=%d pinged=%d security_tested=%d rejected=%d unsupported=%d sources=%d", snapshot.Total, snapshot.Pinged, snapshot.SecurityTested, snapshot.Rejected, snapshot.Unsupported, snapshot.SourceConfigured)
	if err := ensureCoreBinaries(cfg, logger); err != nil {
		logger.console("core", "bootstrap warning: %v", err)
		logger.file("core", "bootstrap warning: %v", err)
	}
	if err := ensureTelegramRuntime(cfg, logger); err != nil {
		logger.console("telegram", "runtime warning: %v", err)
		logger.file("telegram", "runtime warning: %v", err)
	}
	for _, item := range runHealthChecks(cfg, logger) {
		status := "OK"
		if !item.OK {
			status = "FAIL"
		}
		logger.console(item.Section, "%s %-12s %s", status, item.Name, item.Detail)
		logger.file(item.Section, "%s %-12s %s", status, item.Name, item.Detail)
	}
}

func runDaemon(cfg Config, state *State, logger Logger, controller *RuntimeController) error {
	interval := time.Duration(cfg.Schedule.SourceCheckEveryMinutes) * time.Minute
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	nextSourceAt := time.Now().UTC()
	counters := TestCounters{}
	precheckedQueue := []string{}
	precheckedQueueTotal := 0
	if logger.ui != nil {
		logger.ui.SetCycleStart(time.Now().UTC())
		logger.ui.SetPhase("daemon", "continuous collector/tester active")
		logger.ui.SetSyncInfo(fallback(state.LastSourceCheck, "never"), fallback(state.LastGitHubSync, "never"))
	}
	for {
		now := time.Now().UTC()
		if applyRuntimeCommands(cfg, state, logger, controller, &nextSourceAt) {
			return saveState(cfg.Paths.StateFile, state)
		}
		pendingCount := pendingTestCount(cfg, state, now)
		paused := controllerPaused(controller)
		if logger.ui != nil {
			logger.ui.SetSnapshot(snapshotState(cfg, state))
			logger.ui.SetRuntimeState(pendingCount, nextSourceAt, paused)
			logger.ui.SetTestCounters(counters.Done, counters.OK, counters.Failed, counters.Rejected, counters.Skipped, counters.Unsupported)
		}
		if now.After(nextSourceAt) || now.Equal(nextSourceAt) {
			if logger.ui != nil {
				logger.ui.SetPhase("collecting-sources", "refreshing sources on schedule")
			}
			if err := refreshSources(cfg, state, logger, now); err != nil {
				logger.console("source", "scheduled refresh error: %v", err)
				logger.file("source", "scheduled refresh error: %v", err)
			} else {
				state.LastSourceCheck = time.Now().UTC().Format(time.RFC3339)
				precheckedQueue = nil
				precheckedQueueTotal = 0
				if logger.ui != nil {
					logger.ui.SetSyncInfo(state.LastSourceCheck, fallback(state.LastGitHubSync, "never"))
				}
				if err := saveState(cfg.Paths.StateFile, state); err != nil {
					logger.file("scheduler", "save after source refresh failed: %v", err)
				}
			}
			nextSourceAt = time.Now().UTC().Add(interval)
			maybeSyncGitHubProgress(cfg, state, logger, time.Now().UTC())
			continue
		}
		if paused {
			time.Sleep(300 * time.Millisecond)
			continue
		}
		pendingKeys := pendingRecordKeysForTesting(cfg, state, now)
		if len(pendingKeys) == 0 {
			precheckedQueue = nil
			precheckedQueueTotal = 0
			if logger.ui != nil {
				logger.ui.SetTCPPrecheckProgress(0, 0)
				logger.ui.SetTCPPrecheckCounters(0, 0)
				logger.ui.SetTestProgress(0, 0, "waiting for pending tests")
			}
			maybeSyncGitHubProgress(cfg, state, logger, now)
			time.Sleep(300 * time.Millisecond)
			continue
		}
		if !sameStringValues(precheckedQueue, pendingKeys) {
			queue, changed := buildPrecheckedPassQueue(cfg, state, logger, now, &counters, pendingKeys)
			precheckedQueue = queue
			precheckedQueueTotal = len(precheckedQueue)
			if changed {
				if err := saveState(cfg.Paths.StateFile, state); err != nil {
					logger.file("scheduler", "save after tcp precheck batch failed: %v", err)
				}
			}
		}
		if len(precheckedQueue) == 0 {
			precheckedQueueTotal = 0
			if logger.ui != nil {
				logger.ui.SetTCPPrecheckProgress(0, 0)
				logger.ui.SetTestProgress(0, 0, "waiting for pending tests")
			}
			maybeSyncGitHubProgress(cfg, state, logger, now)
			time.Sleep(300 * time.Millisecond)
			continue
		}
		key := precheckedQueue[0]
		precheckedQueue = precheckedQueue[1:]
		rec := state.Records[key]
		if rec == nil || rec.Rejected || !needsTestingNow(*rec, cfg, now) {
			continue
		}
		currentIndex := precheckedQueueTotal - len(precheckedQueue)
		if currentIndex <= 0 {
			currentIndex = 1
		}
		queueTotal := maxInt(precheckedQueueTotal, 1)
		if err := processSingleRecord(cfg, state, logger, rec, now, currentIndex, queueTotal, &counters); err != nil {
			logger.console("testing", "record error endpoint=%s err=%v", rec.EndpointKey, err)
			logger.file("testing", "record error endpoint=%s err=%v", rec.EndpointKey, err)
		}
		if err := saveState(cfg.Paths.StateFile, state); err != nil {
			logger.file("scheduler", "save after record failed: %v", err)
		}
	}
}

type TestCounters struct {
	Done        int
	OK          int
	Failed      int
	Rejected    int
	Skipped     int
	Unsupported int
}

func controllerPaused(controller *RuntimeController) bool {
	if controller == nil {
		return false
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.paused
}

func applyRuntimeCommands(cfg Config, state *State, logger Logger, controller *RuntimeController, nextSourceAt *time.Time) bool {
	if controller == nil {
		return false
	}
	controller.mu.Lock()
	stopRequested := controller.stopRequested
	forceRefresh := controller.forceRefresh
	healthCheck := controller.healthCheck
	controller.forceRefresh = false
	controller.healthCheck = false
	controller.mu.Unlock()
	if stopRequested {
		logger.console("scheduler", "stop requested from keyboard")
		return true
	}
	if forceRefresh {
		*nextSourceAt = time.Now().UTC()
		logger.console("source", "manual source refresh requested")
	}
	if healthCheck {
		for _, item := range runHealthChecks(cfg, logger) {
			status := "OK"
			if !item.OK {
				status = "FAIL"
			}
			logger.console(item.Section, "%s %-12s %s", status, item.Name, item.Detail)
			logger.file(item.Section, "%s %-12s %s", status, item.Name, item.Detail)
		}
	}
	return false
}

func pendingTestCount(cfg Config, state *State, now time.Time) int {
	return len(pendingRecordKeysForTesting(cfg, state, now))
}

func pendingRecordKeysForTesting(cfg Config, state *State, now time.Time) []string {
	fresh := make([]string, 0)
	retests := make([]string, 0)
	for key, rec := range state.Records {
		if rec.Rejected {
			continue
		}
		if strings.TrimSpace(rec.LastURLTestAt) == "" {
			fresh = append(fresh, key)
			continue
		}
		if needsRetest(*rec, cfg, now) {
			retests = append(retests, key)
		}
	}
	sort.Strings(fresh)
	sort.Strings(retests)
	return append(fresh, retests...)
}

func nextRecordForTesting(cfg Config, state *State, now time.Time) (*Record, int) {
	keys := pendingRecordKeysForTesting(cfg, state, now)
	total := len(keys)
	if len(keys) > 0 {
		return state.Records[keys[0]], total
	}
	return nil, 0
}

func needsTestingNow(rec Record, cfg Config, now time.Time) bool {
	if rec.Rejected {
		return false
	}
	if strings.TrimSpace(rec.LastURLTestAt) == "" {
		return true
	}
	return needsRetest(rec, cfg, now)
}

func processSingleRecord(cfg Config, state *State, logger Logger, rec *Record, now time.Time, index, total int, counters *TestCounters) error {
	rejected, reason := hardReject(*rec)
	rec.Rejected = rejected
	rec.RejectReason = reason
	if rejected {
		rec.Unsupported = false
		rec.UnsupportedReason = ""
		rec.Active = false
		rec.PingOK = false
		rec.SecurityLevel = "rejected"
		rec.NamedRaw = formatNamedRaw(*rec)
		counters.Done++
		counters.Rejected++
		logger.console("security", "reject endpoint=%s reason=%s", rec.EndpointKey, reason)
		logger.file("security", "reject endpoint=%s reason=%s", rec.EndpointKey, reason)
		if logger.ui != nil {
			logger.ui.SetTestProgress(index, total, fmt.Sprintf("%s %s:%d", strings.ToUpper(rec.Protocol), rec.Host, rec.Port))
			logger.ui.SetTestCounters(counters.Done, counters.OK, counters.Failed, counters.Rejected, counters.Skipped, counters.Unsupported)
		}
		maybeSyncGitHubProgress(cfg, state, logger, time.Now().UTC())
		return nil
	}
	if !needsTestingNow(*rec, cfg, now) {
		counters.Skipped++
		if logger.ui != nil {
			logger.ui.SetTestCounters(counters.Done, counters.OK, counters.Failed, counters.Rejected, counters.Skipped, counters.Unsupported)
		}
		return nil
	}
	if logger.ui != nil {
		logger.ui.SetPhase("testing", "testing collected configs one by one")
		logger.ui.SetTestProgress(index, total, fmt.Sprintf("%s %s:%d", strings.ToUpper(rec.Protocol), rec.Host, rec.Port))
	}
	logger.console("testing", "[live] testing %s %s:%d", strings.ToUpper(rec.Protocol), rec.Host, rec.Port)
	result, err := runURLTest(cfg, *rec, logger)
	counters.Done++
	if err != nil {
		counters.Failed++
		rec.Active = false
		rec.PingOK = false
		rec.Unsupported = isUnsupportedError(err)
		if rec.Unsupported {
			counters.Unsupported++
		}
		rec.UnsupportedReason = err.Error()
		rec.LatencyMS = -1
		rec.SpeedMBps = 0
		rec.LastURLTestAt = now.Format(time.RFC3339)
		rec.NamedRaw = formatNamedRaw(*rec)
		logger.file("testing", "test failed endpoint=%s err=%v", rec.EndpointKey, err)
		if logger.ui != nil {
			logger.ui.SetTestCounters(counters.Done, counters.OK, counters.Failed, counters.Rejected, counters.Skipped, counters.Unsupported)
		}
		maybeSyncGitHubProgress(cfg, state, logger, time.Now().UTC())
		return nil
	}
	rec.ActiveSecurityFindings = findingsToStrings(result.SecurityFindings)
	if result.CriticalSecurityFailure {
		counters.Failed++
		rec.Unsupported = false
		rec.UnsupportedReason = ""
		rec.Rejected = true
		rec.RejectReason = firstNonEmpty(strings.Join(rec.ActiveSecurityFindings, "; "), "active security probe failure")
		rec.SecurityLevel = "rejected"
		rec.SecurityIssues = append([]string{}, rec.ActiveSecurityFindings...)
		rec.Active = false
		rec.PingOK = false
		rec.LatencyMS = -1
		rec.SpeedMBps = 0
		rec.LastSecurityAt = now.Format(time.RFC3339)
		rec.LastURLTestAt = now.Format(time.RFC3339)
		rec.NamedRaw = formatNamedRaw(*rec)
		logger.console("security", "active reject %s %s", rec.EndpointKey, rec.RejectReason)
		logger.file("security", "active reject endpoint=%s findings=%v", rec.EndpointKey, rec.ActiveSecurityFindings)
		if logger.ui != nil {
			logger.ui.SetTestCounters(counters.Done, counters.OK, counters.Failed, counters.Rejected, counters.Skipped, counters.Unsupported)
		}
		maybeSyncGitHubProgress(cfg, state, logger, time.Now().UTC())
		return nil
	}
	counters.OK++
	rec.Unsupported = false
	rec.UnsupportedReason = ""
	rec.Active = result.PingOK
	rec.PingOK = result.PingOK
	rec.LatencyMS = result.LatencyMS
	rec.SpeedMBps = result.SpeedMBps
	rec.OutboundIP = result.Geo.IP
	if result.Geo.Country != "" {
		rec.Country = result.Geo.Country
		rec.CountryCode = result.Geo.CountryCode
		rec.StateName = result.Geo.State
		rec.Flag = result.Geo.Flag
	}
	if result.Geo.IP != "" || result.Geo.CountryCode != "" || result.Geo.Country != "" {
		rec.LastGeoLookupAt = now.Format(time.RFC3339)
	}
	score, level, issues := scoreSecurity(*rec, result.SecurityFindings)
	rec.SecurityScore = score
	rec.SecurityLevel = level
	rec.SecurityIssues = issues
	rec.LastSecurityAt = now.Format(time.RFC3339)
	rec.LastURLTestAt = now.Format(time.RFC3339)
	rec.NamedRaw = formatNamedRaw(*rec)
	logger.console("testing", "ok %s %dms %s %s", rec.EndpointKey, rec.LatencyMS, formatSpeedKBps(rec.SpeedMBps), rec.SecurityLevel)
	logger.file("testing", "ok endpoint=%s latency=%d speed_mbps=%.4f speed_kbps=%.1f security=%s score=%d", rec.EndpointKey, rec.LatencyMS, rec.SpeedMBps, rec.SpeedMBps*1024, rec.SecurityLevel, rec.SecurityScore)
	if logger.ui != nil {
		logger.ui.SetTestCounters(counters.Done, counters.OK, counters.Failed, counters.Rejected, counters.Skipped, counters.Unsupported)
	}
	maybeSyncGitHubProgress(cfg, state, logger, time.Now().UTC())
	return nil
}

func runCycle(cfg Config, state *State, logger Logger, forceGitHub bool) error {
	startedAt := time.Now().UTC()
	if logger.ui != nil {
		logger.ui.SetCycleStart(startedAt)
		logger.ui.SetPhase("collecting-sources", "collecting sources before testing")
		logger.ui.SetSnapshot(snapshotState(cfg, state))
		logger.ui.SetSyncInfo(fallback(state.LastSourceCheck, "never"), fallback(state.LastGitHubSync, "never"))
	}
	logger.console("scheduler", "cycle started at %s", startedAt.Format(time.RFC3339))
	logger.file("scheduler", "cycle started")
	if err := ensureTelegramRuntime(cfg, logger); err != nil {
		logger.console("telegram", "runtime warning: %v", err)
		logger.file("telegram", "runtime warning: %v", err)
	}

	if err := refreshSources(cfg, state, logger, startedAt); err != nil {
		return err
	}
	if err := ensureCoreBinaries(cfg, logger); err != nil {
		logger.console("core", "bootstrap warning: %v", err)
		logger.file("core", "bootstrap warning: %v", err)
	}
	if logger.ui != nil {
		logger.ui.SetPhase("testing", "testing collected configs one by one")
	}
	if err := processRecords(cfg, state, logger, startedAt); err != nil {
		return err
	}
	if logger.ui != nil {
		logger.ui.SetPhase("writing-outputs", "writing categorized outputs")
	}
	if err := writeOutputs(cfg, state, logger); err != nil {
		return err
	}
	finishedAt := time.Now().UTC()
	if logger.ui != nil {
		logger.ui.SetPhase("github-sync", "syncing github outputs")
	}
	if cfg.GitHub.Enabled && cfg.GitHub.Token != "" && cfg.GitHub.Repository != "" {
		if err := syncGitHub(cfg, state, logger); err != nil {
			logger.console("github", "sync failed: %v", err)
			logger.file("github", "sync failed: %v", err)
		} else {
			state.LastGitHubSync = time.Now().UTC().Format(time.RFC3339)
		}
	}
	state.LastSourceCheck = finishedAt.Format(time.RFC3339)
	snapshot := snapshotState(cfg, state)
	if logger.ui != nil {
		logger.ui.SetSnapshot(snapshot)
		logger.ui.SetSyncInfo(state.LastSourceCheck, fallback(state.LastGitHubSync, "never"))
		logger.ui.SetPhase("idle", "cycle completed")
	}
	logger.console("scheduler", "cycle finished duration=%s records=%d pinged=%d security_tested=%d rejected=%d", finishedAt.Sub(startedAt).Round(time.Second), snapshot.Total, snapshot.Pinged, snapshot.SecurityTested, snapshot.Rejected)
	logger.file("scheduler", "cycle finished duration=%s records=%d pinged=%d security_tested=%d rejected=%d", finishedAt.Sub(startedAt).Round(time.Second), snapshot.Total, snapshot.Pinged, snapshot.SecurityTested, snapshot.Rejected)
	return saveState(cfg.Paths.StateFile, state)
}

func shouldSyncGitHub(cfg Config, state *State, now time.Time, force bool) bool {
	if !cfg.GitHub.Enabled || cfg.GitHub.Token == "" || cfg.GitHub.Repository == "" {
		return false
	}
	if force {
		return true
	}
	last, ok := parseTime(state.LastGitHubSync)
	if !ok {
		return true
	}
	return now.Sub(last) >= time.Duration(cfg.GitHub.SyncEveryMinutes)*time.Minute
}

func refreshSources(cfg Config, state *State, logger Logger, now time.Time) error {
	changed := 0
	unchanged := 0
	failed := 0
	newRecords := 0
	pendingRawSources := make(map[string][]string)
	enabledSources := make([]SourceSpec, 0, len(cfg.Sources))
	for _, source := range cfg.Sources {
		if source.Enabled {
			enabledSources = append(enabledSources, source)
		}
	}
	for index, source := range enabledSources {
		if logger.ui != nil {
			logger.ui.SetSourceProgress(index+1, len(enabledSources), source.Name)
			logger.ui.SetPhase("collecting-sources", "fetching "+source.Name)
		}
		content, sourceID, err := fetchSourceContent(source, cfg, logger)
		if err != nil {
			failed++
			logger.console("source", "source=%s error=%v", source.Name, err)
			logger.file("source", "source=%s error=%v", source.Name, err)
			st := state.Sources[source.Name]
			st.LastError = err.Error()
			state.Sources[source.Name] = st
			continue
		}
		hash := sha1Hex(content)
		if state.Sources[source.Name].Hash == hash {
			unchanged++
			logger.console("source", "source=%s unchanged", source.Name)
			continue
		}
		changed++
		matches := extractProxyLinks(content)
		logger.console("source", "source=%s new_content=%d links=%d via=%s", source.Name, len(content), len(matches), sourceID)
		logger.file("source", "source=%s links=%d via=%s", source.Name, len(matches), sourceID)
		for _, raw := range matches {
			pendingRawSources[raw] = appendUnique(pendingRawSources[raw], source.Name)
		}
		state.Sources[source.Name] = SourceState{
			Hash:          hash,
			LastSuccessAt: now.Format(time.RFC3339),
			LastError:     "",
		}
		if logger.ui != nil {
			logger.ui.SetSnapshot(snapshotState(cfg, state))
		}
	}
	if len(pendingRawSources) > 0 {
		raws := make([]string, 0, len(pendingRawSources))
		for raw := range pendingRawSources {
			raws = append(raws, raw)
		}
		sort.Strings(raws)
		if logger.ui != nil {
			logger.ui.SetPhase("parsing-links", fmt.Sprintf("parsing %d unique links", len(raws)))
		}
		for idx, raw := range raws {
			if logger.ui != nil {
				logger.ui.SetSourceProgress(idx+1, len(raws), fmt.Sprintf("parse %d/%d", idx+1, len(raws)))
			}
			parsed, err := parseProxy(raw)
			if err != nil {
				logger.file("parsing", "drop raw parse error: %v", err)
				continue
			}
			key := endpointKey(parsed.Host, parsed.Port)
			rec, exists := state.Records[key]
			if !exists {
				newRecords++
				rec = &Record{
					EndpointKey:   key,
					ID:            shortHash(parsed.Protocol + "|" + key),
					Protocol:      parsed.Protocol,
					Raw:           parsed.Raw,
					NamedRaw:      parsed.Raw,
					Host:          parsed.Host,
					Port:          parsed.Port,
					Remarks:       parsed.Remarks,
					SecurityLevel: "unknown",
					SecurityScore: 0,
					LatencyMS:     -1,
					SourceNames:   []string{},
					Details:       parsed.Details,
				}
				state.Records[key] = rec
			}
			rec.Protocol = parsed.Protocol
			rec.Raw = parsed.Raw
			rec.Host = parsed.Host
			rec.Port = parsed.Port
			rec.Remarks = parsed.Remarks
			rec.Details = parsed.Details
			rec.LastSeenAt = now.Format(time.RFC3339)
			for _, sourceName := range pendingRawSources[raw] {
				rec.SourceNames = appendUnique(rec.SourceNames, sourceName)
			}
			geo := inferGeoHint(cfg, parsed.Host, parsed.Remarks)
			rec.Country = firstNonEmpty(geo.Country, rec.Country, "Unknown")
			rec.CountryCode = firstNonEmpty(geo.CountryCode, rec.CountryCode, "UN")
			if strings.TrimSpace(rec.StateName) == "" {
				rec.StateName = geo.State
			}
			rec.Flag = firstNonEmpty(geo.Flag, rec.Flag, countryFlag(rec.CountryCode))
			rec.NamedRaw = formatNamedRaw(*rec)
		}
	}
	if logger.ui != nil {
		logger.ui.SetSourceProgress(len(enabledSources), len(enabledSources), "all sources collected")
		logger.ui.SetSnapshot(snapshotState(cfg, state))
	}
	logger.console("source", "summary changed=%d unchanged=%d failed=%d new_records=%d total_records=%d", changed, unchanged, failed, newRecords, len(state.Records))
	logger.file("source", "summary changed=%d unchanged=%d failed=%d new_records=%d total_records=%d", changed, unchanged, failed, newRecords, len(state.Records))
	return nil
}

func fetchSourceContent(source SourceSpec, cfg Config, logger Logger) (string, string, error) {
	if strings.EqualFold(source.Type, "telegram") {
		return fetchTelegramSourceContent(source, cfg, logger)
	}
	links := make([]string, 0, len(source.Links)+1)
	links = append(links, source.Links...)
	if len(links) == 0 {
		return "", "", errors.New("no links configured")
	}
	client := newHTTPClient(cfg.Probes.TimeoutSeconds, nil)
	for _, link := range links {
		body, err := httpGetBody(client, link)
		if err == nil && strings.TrimSpace(body) != "" {
			return body, link, nil
		}
		logger.file("source", "source=%s fallback failed url=%s err=%v", source.Name, link, err)
	}
	return "", "", errors.New("all fallbacks failed")
}

func fetchTelegramSourceContent(source SourceSpec, cfg Config, logger Logger) (string, string, error) {
	channel := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(source.Channel, "https://t.me/"), "@"))
	if channel == "" {
		return "", "", errors.New("telegram channel missing")
	}
	client := newHTTPClient(maxInt(cfg.Probes.TimeoutSeconds, 18), nil)
	webURL := "https://t.me/s/" + channel
	body, err := httpGetTelegramWebBody(client, webURL)
	if err == nil && strings.TrimSpace(body) != "" {
		return body, webURL, nil
	}
	logger.file("source", "telegram web fallback failed channel=%s err=%v", channel, err)
	links, apiErr := telegramDumpViaAPI(cfg, channel, 120)
	if apiErr == nil && len(links) > 0 {
		logger.file("source", "telegram api fallback ok channel=%s links=%d", channel, len(links))
		return strings.Join(links, "\n"), "telegram-api://" + channel, nil
	}
	if apiErr != nil {
		logger.file("source", "telegram api fallback failed channel=%s err=%v", channel, apiErr)
		return "", "", fmt.Errorf("telegram web failed and api fallback failed: %w", apiErr)
	}
	return "", "", errors.New("telegram source returned no links")
}

func httpGetTelegramWebBody(client *http.Client, rawURL string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("status=%d body=%s", resp.StatusCode, trimForDisplay(strings.TrimSpace(string(body)), 120))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func extractProxyLinks(content string) []string {
	decoded := normalizeRawLink(content)
	trimmed := strings.TrimSpace(decoded)
	if !strings.Contains(trimmed, "://") && base64OnlyPattern.MatchString(trimmed) {
		if plain := decodeBase64(trimmed); strings.Contains(plain, "://") {
			decoded = normalizeRawLink(plain)
		}
	}
	seen := make(map[string]struct{})
	result := make([]string, 0, 32)
	appendMatches := func(text string) {
		for _, match := range urlPattern.FindAllString(text, -1) {
			for _, part := range splitEmbeddedLinks(match) {
				clean := cleanExtractedLink(part)
				if !shouldKeepExtractedLink(clean) {
					continue
				}
				if _, ok := seen[clean]; ok {
					continue
				}
				seen[clean] = struct{}{}
				result = append(result, clean)
			}
		}
	}
	appendMatches(decoded)
	for _, line := range strings.Split(decoded, "\n") {
		line = normalizeRawLink(line)
		if line == "" || strings.Contains(line, "://") || !base64OnlyPattern.MatchString(line) {
			continue
		}
		plain := decodeBase64(line)
		if plain != line && strings.Contains(plain, "://") {
			appendMatches(plain)
		}
	}
	appendJSONConfigCandidate := func(candidate string) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || (!strings.HasPrefix(candidate, "{") && !strings.HasPrefix(candidate, "[")) {
			return
		}
		var payload any
		if json.Unmarshal([]byte(candidate), &payload) != nil {
			return
		}
		link := "json://" + base64.StdEncoding.EncodeToString([]byte(candidate))
		if _, ok := seen[link]; ok {
			return
		}
		seen[link] = struct{}{}
		result = append(result, link)
	}
	if strings.Contains(decoded, `"outbounds"`) || strings.Contains(decoded, `"outbound"`) {
		appendJSONConfigCandidate(strings.TrimSpace(decoded))
		for _, line := range strings.Split(decoded, "\n") {
			appendJSONConfigCandidate(line)
		}
	}
	return result
}

func cleanExtractedLink(raw string) string {
	clean := normalizeRawLink(raw)
	clean = strings.Trim(clean, "\"'`[]{}<>")
	for {
		trimmed := strings.TrimRight(clean, ".,;`)")
		trimmed = strings.TrimSpace(trimmed)
		if trimmed == clean {
			return clean
		}
		clean = trimmed
	}
}

func normalizeRawLink(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	raw = html.UnescapeString(raw)
	raw = strings.ReplaceAll(raw, "\u00a0", " ")
	return strings.TrimSpace(raw)
}

func splitEmbeddedLinks(raw string) []string {
	raw = normalizeRawLink(raw)
	if raw == "" {
		return nil
	}
	indexes := linkSchemePattern.FindAllStringIndex(raw, -1)
	if len(indexes) <= 1 {
		return []string{raw}
	}
	starts := []int{0}
	for i := 1; i < len(indexes); i++ {
		if shouldSplitEmbeddedLink(raw, indexes[i][0]) {
			starts = append(starts, indexes[i][0])
		}
	}
	out := make([]string, 0, len(starts))
	for i, start := range starts {
		end := len(raw)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		part := strings.TrimSpace(raw[start:end])
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return []string{raw}
	}
	return out
}

func shouldSplitEmbeddedLink(raw string, index int) bool {
	if index <= 0 || index >= len(raw) {
		return false
	}
	switch raw[index-1] {
	case '=', '&', '+', '?', '/', '%', ':', '_', '-', '.':
		return false
	default:
		return true
	}
}

func shouldKeepExtractedLink(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return true
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	switch host {
	case "t.me", "www.t.me", "telegram.me", "www.telegram.me", "telegram.dog", "www.telegram.dog":
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks", "socks4", "socks4a", "socks5":
		return parsed.Port() != ""
	default:
		return true
	}
}

func selectProbeURLs(urls []string, useAll bool) []string {
	selected := make([]string, 0, len(urls))
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		selected = append(selected, raw)
		if !useAll {
			break
		}
	}
	return selected
}

func selectProbeAttempts(urls []string, useAll, allowFallback bool) []string {
	if useAll || allowFallback {
		return selectProbeURLs(urls, true)
	}
	return selectProbeURLs(urls, false)
}

func parseProxy(raw string) (*ParsedProxy, error) {
	raw = normalizeRawLink(raw)
	if raw == "" {
		return nil, errors.New("empty raw")
	}
	schemeIndex := strings.Index(raw, "://")
	if schemeIndex == -1 {
		return nil, errors.New("missing scheme")
	}
	protocol := normalizeProtocol(strings.ToLower(raw[:schemeIndex]))
	if _, ok := supportedLinkProtocols[protocol]; !ok && protocol != "json" {
		return nil, fmt.Errorf("unsupported protocol %s", protocol)
	}
	contentPart, remarks := splitRemarks(raw)
	if protocol == "json" {
		return parseJSONConfig(raw, contentPart, remarks)
	}
	switch protocol {
	case "vmess":
		return parseVMess(raw, contentPart, remarks)
	case "ss":
		return parseSS(raw, contentPart, remarks)
	case "ssr":
		return parseSSR(raw, contentPart, remarks)
	default:
		return parseGeneric(raw, contentPart, remarks, protocol)
	}
}

func parseJSONConfig(raw, contentPart, remarks string) (*ParsedProxy, error) {
	decoded := decodeBase64(strings.TrimPrefix(contentPart, "json://"))
	var cfg map[string]any
	if err := json.Unmarshal([]byte(decoded), &cfg); err != nil {
		return nil, err
	}
	detection := detectJSONConfig(cfg)
	if detection.engine == "" {
		return nil, errors.New("unknown json config engine")
	}
	host := firstNonEmpty(
		asString(detection.node["server"]),
		asString(detection.node["address"]),
		asString(detection.node["host"]),
		asString(detection.node["listen"]),
	)
	port := intFromAny(firstNonEmptyAny(detection.node["server_port"], detection.node["port"], detection.node["listen_port"]))
	if port == 0 {
		port = defaultPortForProtocol(detection.protocol)
	}
	if host == "" {
		host = "json-" + shortHash(raw)
	}
	if remarks == "" {
		remarks = asString(cfg["remarks"])
	}
	details := map[string]any{
		"json_engine":            detection.engine,
		"json_config":            cfg,
		"json_primary_direction": detection.direction,
		"json_inbound_types":     detection.inboundTypes,
		"json_outbound_types":    detection.outboundTypes,
		"json_primary_tag":       detection.tag,
		"params":                 map[string]any{},
	}
	for key, value := range detection.node {
		details[key] = value
	}
	return &ParsedProxy{
		Protocol: normalizeProtocol(detection.protocol),
		Raw:      raw,
		Host:     normalizeHost(host),
		Port:     port,
		Remarks:  remarks,
		Details:  details,
	}, nil
}

func detectJSONConfig(cfg map[string]any) jsonConfigDetection {
	detection := jsonConfigDetection{
		inboundTypes:  make([]string, 0, 4),
		outboundTypes: make([]string, 0, 4),
	}
	var (
		firstOutbound       map[string]any
		firstInbound        map[string]any
		preferredOutbound   map[string]any
		preferredOutboundTy string
		preferredInbound    map[string]any
		preferredInboundTy  string
	)
	if outbounds, ok := cfg["outbounds"].([]any); ok {
		for _, item := range outbounds {
			outbound := asMap(item)
			protocol := normalizeProtocol(firstNonEmpty(asString(outbound["type"]), asString(outbound["protocol"])))
			if protocol == "" {
				continue
			}
			detection.outboundTypes = appendUnique(detection.outboundTypes, protocol)
			if firstOutbound == nil {
				firstOutbound = outbound
			}
			if preferredOutbound == nil && protocol != "direct" && protocol != "block" {
				preferredOutbound = outbound
				preferredOutboundTy = protocol
			}
		}
	}
	if outbound := asMap(cfg["outbound"]); len(outbound) > 0 {
		protocol := normalizeProtocol(firstNonEmpty(asString(outbound["type"]), asString(outbound["protocol"])))
		if protocol != "" {
			detection.outboundTypes = appendUnique(detection.outboundTypes, protocol)
			if firstOutbound == nil {
				firstOutbound = outbound
			}
			if preferredOutbound == nil && protocol != "direct" && protocol != "block" {
				preferredOutbound = outbound
				preferredOutboundTy = protocol
			}
		}
	}
	if inbounds, ok := cfg["inbounds"].([]any); ok {
		for _, item := range inbounds {
			inbound := asMap(item)
			protocol := normalizeProtocol(firstNonEmpty(asString(inbound["type"]), asString(inbound["protocol"])))
			if protocol == "" {
				continue
			}
			detection.inboundTypes = appendUnique(detection.inboundTypes, protocol)
			if firstInbound == nil {
				firstInbound = inbound
			}
			if preferredInbound == nil && protocol != "http" && protocol != "socks" {
				preferredInbound = inbound
				preferredInboundTy = protocol
			}
		}
	}
	if inbound := asMap(cfg["inbound"]); len(inbound) > 0 {
		protocol := normalizeProtocol(firstNonEmpty(asString(inbound["type"]), asString(inbound["protocol"])))
		if protocol != "" {
			detection.inboundTypes = appendUnique(detection.inboundTypes, protocol)
			if firstInbound == nil {
				firstInbound = inbound
			}
			if preferredInbound == nil && protocol != "http" && protocol != "socks" {
				preferredInbound = inbound
				preferredInboundTy = protocol
			}
		}
	}
	switch {
	case preferredOutbound != nil:
		detection.node = preferredOutbound
		detection.protocol = preferredOutboundTy
		detection.direction = "outbound"
	case preferredInbound != nil:
		detection.node = preferredInbound
		detection.protocol = preferredInboundTy
		detection.direction = "inbound"
	case firstOutbound != nil:
		detection.node = firstOutbound
		detection.protocol = normalizeProtocol(firstNonEmpty(asString(firstOutbound["type"]), asString(firstOutbound["protocol"])))
		detection.direction = "outbound"
	case firstInbound != nil:
		detection.node = firstInbound
		detection.protocol = normalizeProtocol(firstNonEmpty(asString(firstInbound["type"]), asString(firstInbound["protocol"])))
		detection.direction = "inbound"
	default:
		return jsonConfigDetection{}
	}
	detection.engine = "sing-box"
	if asString(detection.node["protocol"]) != "" {
		detection.engine = "xray"
	}
	detection.tag = asString(detection.node["tag"])
	return detection
}

func splitRemarks(raw string) (string, string) {
	hashIndex := strings.Index(raw, "#")
	if hashIndex == -1 {
		return normalizeRawLink(raw), ""
	}
	remarks, err := url.QueryUnescape(raw[hashIndex+1:])
	if err != nil {
		remarks = raw[hashIndex+1:]
	}
	return normalizeRawLink(raw[:hashIndex]), strings.TrimSpace(html.UnescapeString(remarks))
}

func parseVMess(raw, contentPart, remarks string) (*ParsedProxy, error) {
	decoded := decodeBase64(strings.TrimPrefix(contentPart, "vmess://"))
	var cfg map[string]any
	if err := json.Unmarshal([]byte(decoded), &cfg); err != nil {
		return nil, err
	}
	host := strings.TrimSpace(asString(cfg["add"]))
	port, err := parsePort(asString(cfg["port"]), 80)
	if err != nil {
		return nil, err
	}
	if remarks == "" {
		remarks = asString(cfg["ps"])
	}
	return &ParsedProxy{
		Protocol: "vmess",
		Raw:      raw,
		Host:     normalizeHost(host),
		Port:     port,
		Remarks:  remarks,
		Details:  cfg,
	}, nil
}

func parseSS(raw, contentPart, remarks string) (*ParsedProxy, error) {
	body := strings.TrimPrefix(contentPart, "ss://")
	query := ""
	if idx := strings.Index(body, "?"); idx >= 0 {
		query = body[idx+1:]
		body = body[:idx]
	}
	host := ""
	port := 8388
	method := ""
	password := ""
	if at := strings.LastIndex(body, "@"); at >= 0 {
		auth := decodeBase64(body[:at])
		method, password = splitAuthPair(auth)
		host, port = splitHostPort(body[at+1:], 8388)
	} else {
		decoded := decodeBase64(body)
		if at := strings.LastIndex(decoded, "@"); at >= 0 {
			method, password = splitAuthPair(decoded[:at])
			host, port = splitHostPort(decoded[at+1:], 8388)
		} else {
			return nil, errors.New("invalid ss format")
		}
	}
	details := map[string]any{
		"method":   method,
		"password": password,
		"params":   parseQueryMap(query),
	}
	return &ParsedProxy{
		Protocol: "ss",
		Raw:      raw,
		Host:     normalizeHost(host),
		Port:     port,
		Remarks:  remarks,
		Details:  details,
	}, nil
}

func parseSSR(raw, contentPart, remarks string) (*ParsedProxy, error) {
	decoded := decodeBase64(strings.TrimPrefix(contentPart, "ssr://"))
	mainPart := decoded
	query := ""
	if idx := strings.Index(decoded, "?"); idx >= 0 {
		mainPart = decoded[:idx]
		query = decoded[idx+1:]
	}
	parts := strings.Split(mainPart, ":")
	if len(parts) < 6 {
		return nil, errors.New("invalid ssr format")
	}
	host := normalizeHost(parts[0])
	port, err := parsePort(parts[1], 8388)
	if err != nil {
		return nil, err
	}
	password := decodeBase64(strings.Split(parts[5], "/")[0])
	params := map[string]any{}
	for key, value := range parseQueryMap(query) {
		params[key] = decodeBase64(asString(value))
	}
	if remarks == "" {
		if val, ok := params["remarks"].(string); ok {
			remarks = val
		}
	}
	return &ParsedProxy{
		Protocol: "ssr",
		Raw:      raw,
		Host:     host,
		Port:     port,
		Remarks:  remarks,
		Details: map[string]any{
			"subProtocol": parts[2],
			"method":      parts[3],
			"obfs":        parts[4],
			"password":    password,
			"params":      params,
		},
	}, nil
}

func parseGeneric(raw, contentPart, remarks, protocol string) (*ParsedProxy, error) {
	remainder := strings.TrimPrefix(contentPart, raw[:strings.Index(raw, "://")+3])
	auth := ""
	addressPart := remainder
	if at := strings.LastIndex(remainder, "@"); at >= 0 {
		auth = remainder[:at]
		addressPart = remainder[at+1:]
	}
	query := ""
	if idx := strings.Index(addressPart, "?"); idx >= 0 {
		query = addressPart[idx+1:]
		addressPart = addressPart[:idx]
	}
	host, port := splitHostPort(addressPart, defaultPortForProtocol(protocol))
	if host == "" || port == 0 {
		return nil, errors.New("missing host or port")
	}
	details := map[string]any{
		"auth":   auth,
		"params": parseQueryMap(query),
	}
	switch protocol {
	case "ssh":
		user, pass := splitAuthPair(auth)
		details["user"] = user
		details["password"] = pass
	case "naive":
		user, pass := splitAuthPair(auth)
		details["username"] = user
		details["password"] = pass
	case "wireguard":
		details["private_key"] = auth
	case "shadowtls":
		details["password"] = auth
	case "anytls":
		details["password"] = auth
	case "tor":
		details["version"] = "5"
	case "socks4", "socks4a":
		details["version"] = strings.TrimPrefix(protocol, "socks")
	case "urltest", "selector":
		details["outbounds"] = splitCSV(asString(details["params"].(map[string]any)["outbounds"]))
	}
	if protocol == "https" {
		protocol = "http"
		params := details["params"].(map[string]any)
		params["tls"] = "true"
	}
	return &ParsedProxy{
		Protocol: normalizeProtocol(protocol),
		Raw:      raw,
		Host:     normalizeHost(host),
		Port:     port,
		Remarks:  remarks,
		Details:  details,
	}, nil
}

func processRecords(cfg Config, state *State, logger Logger, now time.Time) error {
	keys := make([]string, 0, len(state.Records))
	for key := range state.Records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	candidates := make([]*Record, 0, len(keys))
	testIndex := 0
	rejectedCount := 0
	skippedCount := 0
	okCount := 0
	failedCount := 0
	unsupportedCount := 0
	for _, key := range keys {
		rec := state.Records[key]
		rejected, reason := hardReject(*rec)
		rec.Rejected = rejected
		rec.RejectReason = reason
		if rejected {
			rec.Unsupported = false
			rec.UnsupportedReason = ""
			rejectedCount++
			rec.Active = false
			rec.PingOK = false
			rec.SecurityLevel = "rejected"
			rec.NamedRaw = formatNamedRaw(*rec)
			logger.console("security", "reject endpoint=%s reason=%s", rec.EndpointKey, reason)
			logger.file("security", "reject endpoint=%s reason=%s", rec.EndpointKey, reason)
			if logger.ui != nil {
				logger.ui.SetTestCounters(testIndex, okCount, failedCount, rejectedCount, skippedCount, unsupportedCount)
			}
			maybeSyncGitHubProgress(cfg, state, logger, time.Now().UTC())
			continue
		}
		if !needsRetest(*rec, cfg, now) {
			skippedCount++
			if logger.ui != nil {
				logger.ui.SetTestCounters(testIndex, okCount, failedCount, rejectedCount, skippedCount, unsupportedCount)
			}
			continue
		}
		candidates = append(candidates, rec)
	}
	totalCandidates := len(candidates)
	precheckResults := map[string]tcpPrecheckStatus{}
	if cfg.Probes.EnableTCPPrecheck && totalCandidates > 0 {
		precheckResults = runParallelTCPPrechecks(cfg, candidates, logger)
	}
	for _, rec := range candidates {
		testIndex++
		if logger.ui != nil {
			logger.ui.SetTestProgress(testIndex, totalCandidates, fmt.Sprintf("%s %s:%d", strings.ToUpper(rec.Protocol), rec.Host, rec.Port))
			logger.ui.SetTestCounters(testIndex, okCount, failedCount, rejectedCount, skippedCount, unsupportedCount)
			if testIndex == 1 || testIndex%10 == 0 || testIndex == totalCandidates {
				logger.ui.SetSnapshot(snapshotState(cfg, state))
			}
		}
		if precheck, ok := precheckResults[rec.EndpointKey]; ok && precheck.Attempted && !precheck.OK {
			failedCount++
			applyTCPPrecheckFailure(rec, precheck.Err, now)
			logger.console("testing", "[%d/%d] tcp gate failed %s %s:%d", testIndex, maxInt(totalCandidates, 1), strings.ToUpper(rec.Protocol), rec.Host, rec.Port)
			logger.file("testing", "tcp gate failed endpoint=%s err=%v", rec.EndpointKey, precheck.Err)
			if logger.ui != nil {
				logger.ui.SetTestCounters(testIndex, okCount, failedCount, rejectedCount, skippedCount, unsupportedCount)
			}
			maybeSyncGitHubProgress(cfg, state, logger, time.Now().UTC())
			continue
		}
		logger.console("testing", "[%d/%d] testing %s %s:%d", testIndex, maxInt(totalCandidates, 1), strings.ToUpper(rec.Protocol), rec.Host, rec.Port)
		result, err := runURLTest(cfg, *rec, logger)
		if err != nil {
			failedCount++
			rec.Active = false
			rec.PingOK = false
			rec.Unsupported = isUnsupportedError(err)
			if rec.Unsupported {
				unsupportedCount++
			}
			rec.UnsupportedReason = err.Error()
			rec.LatencyMS = -1
			rec.SpeedMBps = 0
			rec.LastURLTestAt = now.Format(time.RFC3339)
			rec.NamedRaw = formatNamedRaw(*rec)
			logger.file("testing", "test failed endpoint=%s err=%v", rec.EndpointKey, err)
			if logger.ui != nil {
				logger.ui.SetTestCounters(testIndex, okCount, failedCount, rejectedCount, skippedCount, unsupportedCount)
			}
			maybeSyncGitHubProgress(cfg, state, logger, time.Now().UTC())
			continue
		}
		rec.ActiveSecurityFindings = findingsToStrings(result.SecurityFindings)
		if result.CriticalSecurityFailure {
			failedCount++
			rec.Unsupported = false
			rec.UnsupportedReason = ""
			rec.Rejected = true
			rec.RejectReason = firstNonEmpty(strings.Join(rec.ActiveSecurityFindings, "; "), "active security probe failure")
			rec.SecurityLevel = "rejected"
			rec.SecurityIssues = append([]string{}, rec.ActiveSecurityFindings...)
			rec.Active = false
			rec.PingOK = false
			rec.LatencyMS = -1
			rec.SpeedMBps = 0
			rec.LastSecurityAt = now.Format(time.RFC3339)
			rec.LastURLTestAt = now.Format(time.RFC3339)
			rec.NamedRaw = formatNamedRaw(*rec)
			logger.console("security", "active reject %s %s", rec.EndpointKey, rec.RejectReason)
			logger.file("security", "active reject endpoint=%s findings=%v", rec.EndpointKey, rec.ActiveSecurityFindings)
			if logger.ui != nil {
				logger.ui.SetTestCounters(testIndex, okCount, failedCount, rejectedCount, skippedCount, unsupportedCount)
			}
			maybeSyncGitHubProgress(cfg, state, logger, time.Now().UTC())
			continue
		}
		okCount++
		rec.Unsupported = false
		rec.UnsupportedReason = ""
		rec.Active = result.PingOK
		rec.PingOK = result.PingOK
		rec.LatencyMS = result.LatencyMS
		rec.SpeedMBps = result.SpeedMBps
		rec.OutboundIP = result.Geo.IP
		if result.Geo.Country != "" {
			rec.Country = result.Geo.Country
			rec.CountryCode = result.Geo.CountryCode
			rec.StateName = result.Geo.State
			rec.Flag = result.Geo.Flag
		}
		if result.Geo.IP != "" || result.Geo.CountryCode != "" || result.Geo.Country != "" {
			rec.LastGeoLookupAt = now.Format(time.RFC3339)
		}
		score, level, issues := scoreSecurity(*rec, result.SecurityFindings)
		rec.SecurityScore = score
		rec.SecurityLevel = level
		rec.SecurityIssues = issues
		rec.LastSecurityAt = now.Format(time.RFC3339)
		rec.LastURLTestAt = now.Format(time.RFC3339)
		rec.NamedRaw = formatNamedRaw(*rec)
		logger.console("testing", "ok %s %dms %s %s", rec.EndpointKey, rec.LatencyMS, formatSpeedKBps(rec.SpeedMBps), rec.SecurityLevel)
		logger.file("testing", "ok endpoint=%s latency=%d speed_mbps=%.4f speed_kbps=%.1f security=%s score=%d", rec.EndpointKey, rec.LatencyMS, rec.SpeedMBps, rec.SpeedMBps*1024, rec.SecurityLevel, rec.SecurityScore)
		if logger.ui != nil {
			logger.ui.SetTestCounters(testIndex, okCount, failedCount, rejectedCount, skippedCount, unsupportedCount)
		}
		maybeSyncGitHubProgress(cfg, state, logger, time.Now().UTC())
	}
	if logger.ui != nil {
		logger.ui.SetTestProgress(totalCandidates, totalCandidates, "testing finished")
		logger.ui.SetTestCounters(testIndex, okCount, failedCount, rejectedCount, skippedCount, unsupportedCount)
	}
	logger.console("testing", "summary tested=%d ok=%d failed=%d rejected=%d skipped=%d unsupported=%d", totalCandidates, okCount, failedCount, rejectedCount, skippedCount, unsupportedCount)
	logger.file("testing", "summary tested=%d ok=%d failed=%d rejected=%d skipped=%d unsupported=%d", totalCandidates, okCount, failedCount, rejectedCount, skippedCount, unsupportedCount)
	return nil
}

func maybeSyncGitHubProgress(cfg Config, state *State, logger Logger, now time.Time) {
	if !shouldSyncGitHub(cfg, state, now, false) {
		return
	}
	logger.console("github", "mid-cycle sync started")
	logger.file("github", "mid-cycle sync started at %s", now.Format(time.RFC3339))
	if logger.ui != nil {
		logger.ui.SetPhase("github-sync", "syncing tested configs to github")
	}
	if err := writeOutputs(cfg, state, logger); err != nil {
		logger.console("github", "mid-cycle write failed: %v", err)
		logger.file("github", "mid-cycle write failed: %v", err)
		return
	}
	if err := syncGitHub(cfg, state, logger); err != nil {
		logger.console("github", "mid-cycle sync failed: %v", err)
		logger.file("github", "mid-cycle sync failed: %v", err)
	} else {
		state.LastGitHubSync = time.Now().UTC().Format(time.RFC3339)
		if logger.ui != nil {
			logger.ui.SetSyncInfo(fallback(state.LastSourceCheck, "never"), state.LastGitHubSync)
		}
		if err := saveState(cfg.Paths.StateFile, state); err != nil {
			logger.file("github", "mid-cycle state save failed: %v", err)
		}
		logger.console("github", "mid-cycle sync finished")
		logger.file("github", "mid-cycle sync finished")
	}
	if logger.ui != nil {
		logger.ui.SetPhase("testing", "testing collected configs one by one")
		logger.ui.SetSnapshot(snapshotState(cfg, state))
	}
}

func needsRetest(rec Record, cfg Config, now time.Time) bool {
	if rec.Rejected {
		return false
	}
	last, ok := parseTime(rec.LastURLTestAt)
	if !ok {
		return true
	}
	return now.Sub(last) >= time.Duration(cfg.Schedule.RetestEveryHours)*time.Hour
}

type TestResult struct {
	PingOK                  bool
	LatencyMS               int
	SpeedMBps               float64
	Geo                     GeoInfo
	SecurityFindings        []ActiveFinding
	CriticalSecurityFailure bool
}

type testMode int

const (
	testModeUnsupported testMode = iota
	testModeJSON
	testModeConnectivity
	testModeCoreValidation
	testModeSyntheticValidation
)

type protocolTestPlan struct {
	mode    testMode
	useXray bool
	reason  string
}

type ActiveFinding struct {
	Message  string
	Critical bool
	Penalty  int
}

type probeObservation struct {
	Probe         ActiveSecurityProbe
	Status        int
	ContentType   string
	BodyHash      string
	BodyLen       int64
	RedirectCount int
	FinalHost     string
	TLSVersion    string
	TLSExpiresAt  time.Time
	JSONStatus    *int
	JSONAnswers   int
}

func runURLTest(cfg Config, rec Record, logger Logger) (TestResult, error) {
	plan := selectProtocolTestPlan(rec)
	if plan.mode == testModeUnsupported {
		return TestResult{}, unsupportedError{plan.reason}
	}
	switch plan.mode {
	case testModeJSON:
		return testJSONConfig(cfg, rec, logger)
	case testModeConnectivity:
		return testWithLocalCore(cfg, rec, logger, plan.useXray)
	case testModeCoreValidation:
		return validateWithLocalCore(cfg, rec, logger, plan.useXray)
	case testModeSyntheticValidation:
		return testStructurally(rec, plan.reason)
	default:
		return TestResult{}, unsupportedError{plan.reason}
	}
}

func selectProtocolTestPlan(rec Record) protocolTestPlan {
	params := asMap(rec.Details["params"])
	network := normalizeTransport(firstNonEmpty(asString(params["type"]), asString(rec.Details["net"]), "tcp"))
	switch rec.Protocol {
	case "json":
		return protocolTestPlan{mode: testModeJSON}
	case "socks", "http", "tor", "vmess", "vless", "trojan", "ss", "direct":
		switch network {
		case "http":
			return protocolTestPlan{mode: testModeSyntheticValidation, reason: fmt.Sprintf("protocol %s uses legacy http/h2 transport; current xray releases no longer validate it as a live-dial transport", rec.Protocol)}
		case "kcp":
			return protocolTestPlan{mode: testModeSyntheticValidation, reason: fmt.Sprintf("protocol %s uses legacy mkcp transport; current xray releases no longer validate it as a live-dial transport", rec.Protocol)}
		case "quic":
			return protocolTestPlan{mode: testModeSyntheticValidation, reason: fmt.Sprintf("protocol %s uses legacy quic transport; current xray releases no longer validate it as a live-dial transport", rec.Protocol)}
		case "xhttp":
			return protocolTestPlan{mode: testModeSyntheticValidation, reason: fmt.Sprintf("protocol %s uses xhttp transport; bundled xray core cannot live-dial it safely", rec.Protocol)}
		case "uds":
			return protocolTestPlan{mode: testModeSyntheticValidation, reason: fmt.Sprintf("protocol %s uses uds/domain-socket transport; bundled xray core cannot live-dial it safely", rec.Protocol)}
		}
		return protocolTestPlan{mode: testModeConnectivity, useXray: true}
	case "hysteria", "hysteria2", "tuic", "ssh":
		return protocolTestPlan{mode: testModeConnectivity, useXray: false}
	case "naive":
		return protocolTestPlan{mode: testModeSyntheticValidation, reason: "protocol naive is structurally validated because the bundled sing-box core cannot instantiate it"}
	case "wireguard":
		return protocolTestPlan{mode: testModeSyntheticValidation, reason: "protocol wireguard is structurally validated because current sing-box releases removed the legacy outbound form used by this runtime"}
	case "block", "selector", "urltest", "mixed", "tproxy", "redirect", "shadowtls":
		return protocolTestPlan{mode: testModeCoreValidation, useXray: false}
	case "tun":
		return protocolTestPlan{mode: testModeSyntheticValidation, reason: "protocol tun is structurally validated because current sing-box releases removed the legacy inline tun fields used by this runtime"}
	case "tap":
		return protocolTestPlan{mode: testModeSyntheticValidation, reason: "protocol tap is structurally validated because the bundled sing-box core cannot instantiate it"}
	case "dns", "dokodemo-door":
		return protocolTestPlan{mode: testModeCoreValidation, useXray: true}
	case "ssr", "anytls", "tailscale", "juicity", "custom":
		return protocolTestPlan{mode: testModeSyntheticValidation, reason: fmt.Sprintf("protocol %s is structurally validated because bundled cores do not provide a safe live-dial path", rec.Protocol)}
	default:
		return protocolTestPlan{mode: testModeUnsupported, reason: fmt.Sprintf("protocol %s has no tester yet", rec.Protocol)}
	}
}

type unsupportedError struct{ msg string }

func (e unsupportedError) Error() string { return e.msg }

func isUnsupportedError(err error) bool {
	var target unsupportedError
	return errors.As(err, &target)
}

func supportsTCPPrecheck(rec Record) bool {
	params := asMap(rec.Details["params"])
	network := normalizeTransport(firstNonEmpty(asString(params["type"]), asString(rec.Details["net"]), "tcp"))
	switch rec.Protocol {
	case "hysteria", "hysteria2", "hy", "hy2", "tuic", "wireguard", "wg":
		return false
	case "vmess", "vless", "trojan", "json":
		return network != "kcp" && network != "quic"
	default:
		return true
	}
}

func tcpPrecheck(rec Record, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 600 * time.Millisecond
	}
	address := net.JoinHostPort(rec.Host, strconv.Itoa(rec.Port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

type tcpPrecheckStatus struct {
	Attempted bool
	OK        bool
	Err       error
}

func runParallelTCPPrechecks(cfg Config, records []*Record, logger Logger) map[string]tcpPrecheckStatus {
	results := make(map[string]tcpPrecheckStatus, len(records))
	if !cfg.Probes.EnableTCPPrecheck || len(records) == 0 {
		return results
	}
	targets := make([]*Record, 0, len(records))
	for _, rec := range records {
		if rec == nil {
			continue
		}
		plan := selectProtocolTestPlan(*rec)
		if plan.mode != testModeConnectivity || !supportsTCPPrecheck(*rec) {
			continue
		}
		targets = append(targets, rec)
	}
	if len(targets) == 0 {
		return results
	}
	workers := maxInt(runtime.NumCPU()*24, 64)
	if workers > len(targets) {
		workers = len(targets)
	}
	if workers > 256 {
		workers = 256
	}
	timeout := time.Duration(cfg.Probes.TCPPrecheckTimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 600 * time.Millisecond
	}
	if logger.ui != nil {
		logger.ui.SetTCPPrecheckProgress(0, len(targets))
		logger.ui.SetTCPPrecheckCounters(0, 0)
		logger.ui.SetPhase("tcp-precheck", fmt.Sprintf("running parallel tcp reachability precheck for %d configs", len(targets)))
	}
	logger.console("testing", "tcp precheck batch started targets=%d workers=%d", len(targets), workers)
	logger.file("testing", "tcp precheck batch started targets=%d workers=%d timeout=%s", len(targets), workers, timeout)
	jobs := make(chan *Record)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var passedCount atomic.Int64
	var failedCount atomic.Int64
	var completedCount atomic.Int64
	totalTargets := int64(len(targets))
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rec := range jobs {
				err := tcpPrecheck(*rec, timeout)
				status := tcpPrecheckStatus{Attempted: true, OK: err == nil, Err: err}
				mu.Lock()
				results[rec.EndpointKey] = status
				mu.Unlock()
				if err == nil {
					passedCount.Add(1)
				} else {
					failedCount.Add(1)
				}
				done := completedCount.Add(1)
				if logger.ui != nil && (done == totalTargets || done%16 == 0) {
					logger.ui.SetTCPPrecheckProgress(int(done), int(totalTargets))
					logger.ui.SetTCPPrecheckCounters(int(passedCount.Load()), int(failedCount.Load()))
				}
				if err != nil {
					logger.file("testing", "tcp precheck failed endpoint=%s err=%v", rec.EndpointKey, err)
				}
			}
		}()
	}
	for _, rec := range targets {
		jobs <- rec
	}
	close(jobs)
	wg.Wait()
	passed := int(passedCount.Load())
	failed := int(failedCount.Load())
	if logger.ui != nil {
		logger.ui.SetTCPPrecheckProgress(int(totalTargets), int(totalTargets))
		logger.ui.SetTCPPrecheckCounters(passed, failed)
	}
	logger.console("testing", "tcp precheck batch finished passed=%d failed=%d", passed, failed)
	logger.file("testing", "tcp precheck batch finished passed=%d failed=%d", passed, failed)
	return results
}

func applyTCPPrecheckFailure(rec *Record, err error, now time.Time) {
	rec.Active = false
	rec.PingOK = false
	rec.Unsupported = false
	rec.UnsupportedReason = ""
	rec.LatencyMS = -1
	rec.SpeedMBps = 0
	rec.LastURLTestAt = now.Format(time.RFC3339)
	rec.NamedRaw = formatNamedRaw(*rec)
	if err != nil {
		rec.SecurityIssues = []string{"tcp precheck failed: " + err.Error()}
	}
}

func buildPrecheckedPassQueue(cfg Config, state *State, logger Logger, now time.Time, counters *TestCounters, pendingKeys []string) ([]string, bool) {
	records := make([]*Record, 0, len(pendingKeys))
	for _, key := range pendingKeys {
		if rec := state.Records[key]; rec != nil {
			records = append(records, rec)
		}
	}
	results := runParallelTCPPrechecks(cfg, records, logger)
	passKeys := make([]string, 0, len(pendingKeys))
	changed := false
	for _, key := range pendingKeys {
		rec := state.Records[key]
		if rec == nil {
			continue
		}
		precheck, ok := results[key]
		if ok && precheck.Attempted && !precheck.OK {
			changed = true
			counters.Done++
			counters.Failed++
			applyTCPPrecheckFailure(rec, precheck.Err, now)
			logger.console("testing", "[live] tcp gate failed %s %s:%d", strings.ToUpper(rec.Protocol), rec.Host, rec.Port)
			logger.file("testing", "tcp gate failed endpoint=%s err=%v", rec.EndpointKey, precheck.Err)
			if logger.ui != nil {
				logger.ui.SetTestCounters(counters.Done, counters.OK, counters.Failed, counters.Rejected, counters.Skipped, counters.Unsupported)
			}
			continue
		}
		passKeys = append(passKeys, key)
	}
	if changed {
		maybeSyncGitHubProgress(cfg, state, logger, time.Now().UTC())
	}
	return passKeys, changed
}

func sameStringValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func testWithLocalCore(cfg Config, rec Record, logger Logger, useXray bool) (TestResult, error) {
	path := cfg.Cores.SingBoxPath
	if useXray {
		path = cfg.Cores.XrayPath
	}
	if !fileExists(path) {
		return TestResult{}, fmt.Errorf("core binary missing: %s", path)
	}
	port, err := freePort()
	if err != nil {
		return TestResult{}, err
	}
	configPath := filepath.Join(os.TempDir(), fmt.Sprintf("proxyharvest-%d.json", time.Now().UnixNano()))
	var payload map[string]any
	if useXray {
		payload, err = buildXrayConfig(port, rec)
	} else {
		payload, err = buildSingBoxConfig(port, rec)
	}
	if err != nil {
		return TestResult{}, err
	}
	if err := writeJSON(configPath, payload); err != nil {
		return TestResult{}, err
	}
	defer os.Remove(configPath)

	args := []string{"run", "-c", configPath}
	cmd := exec.Command(path, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return TestResult{}, err
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	if err := waitForCoreReady(port, cmd, time.Duration(cfg.Probes.CoreStartupWaitMS)*time.Millisecond); err != nil {
		return TestResult{}, err
	}
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	return runConfigChecks(cfg, rec, proxyURL, logger)
}

func testJSONConfig(cfg Config, rec Record, logger Logger) (TestResult, error) {
	details := rec.Details
	engine := strings.ToLower(asString(details["json_engine"]))
	if engine == "" {
		return TestResult{}, unsupportedError{"json config missing engine metadata"}
	}
	path := cfg.Cores.SingBoxPath
	if engine == "xray" {
		path = cfg.Cores.XrayPath
	}
	if !fileExists(path) {
		return TestResult{}, fmt.Errorf("core binary missing: %s", path)
	}
	rawConfig := deepCloneMap(asMap(details["json_config"]))
	if len(rawConfig) == 0 {
		return TestResult{}, unsupportedError{"json config payload is empty"}
	}
	if reason := jsonSyntheticValidationReason(details, rawConfig); reason != "" {
		return testStructurally(rec, reason)
	}
	if jsonRequiresCoreValidation(details) {
		result, err := validateRawJSONConfig(cfg, engine, rawConfig)
		if err != nil && shouldFallbackToSyntheticValidation(err) {
			return testStructurally(rec, "json config uses features unsupported by the bundled local core; running structural validation instead")
		}
		return result, err
	}
	port, err := freePort()
	if err != nil {
		return TestResult{}, err
	}
	var prepared map[string]any
	switch engine {
	case "xray":
		prepared = prepareXrayJSONConfig(rawConfig, port)
	case "sing-box":
		prepared = prepareSingBoxJSONConfig(rawConfig, port)
	default:
		return TestResult{}, unsupportedError{"unknown json engine: " + engine}
	}
	configPath := filepath.Join(os.TempDir(), fmt.Sprintf("proxyharvest-json-%d.json", time.Now().UnixNano()))
	if err := writeJSON(configPath, prepared); err != nil {
		return TestResult{}, err
	}
	defer os.Remove(configPath)
	cmd := exec.Command(path, "run", "-c", configPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return TestResult{}, err
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	if err := waitForCoreReady(port, cmd, time.Duration(cfg.Probes.CoreStartupWaitMS)*time.Millisecond); err != nil {
		return TestResult{}, err
	}
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	return runConfigChecks(cfg, rec, proxyURL, logger)
}

func validateWithLocalCore(cfg Config, rec Record, logger Logger, useXray bool) (TestResult, error) {
	path := cfg.Cores.SingBoxPath
	if useXray {
		path = cfg.Cores.XrayPath
	}
	if !fileExists(path) {
		return TestResult{}, fmt.Errorf("core binary missing: %s", path)
	}
	var (
		payload map[string]any
		err     error
	)
	if useXray {
		payload, err = buildXrayValidationConfig(rec)
	} else {
		payload, err = buildSingBoxValidationConfig(rec)
	}
	if err != nil {
		return TestResult{}, err
	}
	return runCoreValidation(path, payload, useXray)
}

func validateRawJSONConfig(cfg Config, engine string, payload map[string]any) (TestResult, error) {
	path := cfg.Cores.SingBoxPath
	useXray := engine == "xray"
	if useXray {
		path = cfg.Cores.XrayPath
	}
	if !fileExists(path) {
		return TestResult{}, fmt.Errorf("core binary missing: %s", path)
	}
	return runCoreValidation(path, payload, useXray)
}

func runCoreValidation(path string, payload map[string]any, useXray bool) (TestResult, error) {
	configPath := filepath.Join(os.TempDir(), fmt.Sprintf("proxyharvest-validate-%d.json", time.Now().UnixNano()))
	if err := writeJSON(configPath, payload); err != nil {
		return TestResult{}, err
	}
	defer os.Remove(configPath)
	args := []string{"check", "-c", configPath}
	if useXray {
		args = []string{"run", "-test", "-c", configPath}
	}
	cmd := exec.Command(path, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg != "" {
			return TestResult{}, fmt.Errorf("core validation failed: %s", trimForDisplay(msg, 2000))
		}
		return TestResult{}, fmt.Errorf("core validation failed: %w", err)
	}
	return TestResult{
		PingOK:                  false,
		LatencyMS:               -1,
		SpeedMBps:               0,
		Geo:                     GeoInfo{},
		SecurityFindings:        nil,
		CriticalSecurityFailure: false,
	}, nil
}

func testStructurally(rec Record, reason string) (TestResult, error) {
	if strings.TrimSpace(rec.Host) == "" && rec.Protocol != "custom" {
		return TestResult{}, errors.New("missing host for structural validation")
	}
	if rec.Port < 0 || rec.Port > 65535 {
		return TestResult{}, fmt.Errorf("invalid port %d", rec.Port)
	}
	if strings.TrimSpace(reason) == "" {
		reason = "structural validation only"
	}
	_ = reason
	return TestResult{
		PingOK:                  false,
		LatencyMS:               -1,
		SpeedMBps:               0,
		Geo:                     GeoInfo{},
		SecurityFindings:        nil,
		CriticalSecurityFailure: false,
	}, nil
}

func jsonRequiresCoreValidation(details map[string]any) bool {
	for _, item := range stringSliceFromAny(details["json_inbound_types"]) {
		switch normalizeProtocol(item) {
		case "mixed", "tun", "tproxy", "redirect", "tap", "dokodemo-door":
			return true
		}
	}
	for _, item := range stringSliceFromAny(details["json_outbound_types"]) {
		switch normalizeProtocol(item) {
		case "selector", "urltest", "block", "dns", "shadowtls", "wireguard":
			return true
		}
	}
	return false
}

func jsonSyntheticValidationReason(details map[string]any, payload map[string]any) string {
	engine := strings.ToLower(asString(details["json_engine"]))
	switch engine {
	case "sing-box":
		for _, item := range stringSliceFromAny(details["json_inbound_types"]) {
			if normalizeProtocol(item) == "tap" {
				return "json config uses tap inbound; the bundled sing-box core cannot instantiate it"
			}
		}
		for _, item := range stringSliceFromAny(details["json_outbound_types"]) {
			switch protocol := normalizeProtocol(item); protocol {
			case "naive", "anytls", "tailscale", "juicity", "custom":
				return fmt.Sprintf("json config uses %s outbound; the bundled sing-box core cannot instantiate it", protocol)
			}
		}
	case "xray":
		if transport, ok := jsonContainsTransport(payload, "xhttp", "uds"); ok {
			if transport == "uds" {
				return "json config uses uds/domain-socket transport; the bundled xray core cannot instantiate it"
			}
			return fmt.Sprintf("json config uses %s transport; the bundled xray core cannot instantiate it", transport)
		}
	}
	return ""
}

func jsonContainsTransport(value any, targets ...string) (string, bool) {
	if len(targets) == 0 {
		return "", false
	}
	want := make(map[string]struct{}, len(targets))
	for _, item := range targets {
		normalized := normalizeTransport(item)
		if normalized != "" {
			want[normalized] = struct{}{}
		}
	}
	var walk func(any) (string, bool)
	walk = func(current any) (string, bool) {
		switch typed := current.(type) {
		case map[string]any:
			for key, value := range typed {
				if strings.EqualFold(key, "network") {
					if transport := normalizeTransport(asString(value)); transport != "" {
						if _, ok := want[transport]; ok {
							return transport, true
						}
					}
				}
				if found, ok := walk(value); ok {
					return found, true
				}
			}
		case []any:
			for _, item := range typed {
				if found, ok := walk(item); ok {
					return found, true
				}
			}
		}
		return "", false
	}
	return walk(value)
}

func shouldFallbackToSyntheticValidation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	patterns := []string{
		"unknown outbound type: naive",
		"unknown outbound type: anytls",
		"unknown outbound type: tailscale",
		"unknown outbound type: juicity",
		"unknown inbound type: tap",
		"unknown transport protocol: uds",
		"unknown transport protocol: xhttp",
		"feature http transport",
		"failed to build mkcp config",
		"feature quic transport",
		"legacy tun address fields are deprecated",
		`unknown field "local_address"`,
	}
	for _, pattern := range patterns {
		if strings.Contains(msg, pattern) {
			return true
		}
	}
	return false
}

func effectiveProbeTimeout(cfg Config) time.Duration {
	timeout := time.Duration(cfg.Probes.PerConfigTimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	maxTimeout := time.Duration(cfg.Probes.TimeoutSeconds) * time.Second
	if maxTimeout > 0 && maxTimeout < timeout {
		timeout = maxTimeout
	}
	return timeout
}

func effectiveSecurityProbeTimeout(cfg Config) time.Duration {
	timeout := time.Duration(cfg.Probes.SecurityProbeTimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = effectiveProbeTimeout(cfg)
	}
	return timeout
}

func waitForCoreReady(port int, cmd *exec.Cmd, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	var lastErr error
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return errors.New("local core exited before becoming ready")
		}
		conn, err := net.DialTimeout("tcp", address, 60*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("local core inbound did not become ready")
	}
	return lastErr
}

func fastGeoForRecord(cfg Config, rec Record, proxyURL *url.URL, logger Logger) (GeoInfo, error) {
	if proxyURL != nil {
		ip, err := lookupProxyOutboundIP(cfg, proxyURL)
		if err == nil && ip != "" {
			geo, geoErr := lookupGeoByIP(cfg, ip)
			if geoErr == nil && geo.CountryCode != "" {
				return geo, nil
			}
			logger.file("geo", "proxy ip geo fallback ip=%s err=%v", ip, geoErr)
			geo.IP = ip
			if geo.CountryCode != "" || geo.Country != "" {
				return geo, nil
			}
		} else if err != nil {
			logger.file("geo", "proxy outbound ip lookup failed endpoint=%s err=%v", rec.EndpointKey, err)
		}
	}
	if strings.TrimSpace(rec.OutboundIP) != "" {
		if geo, err := lookupGeoByIP(cfg, rec.OutboundIP); err == nil && geo.CountryCode != "" {
			return geo, nil
		}
	}
	return lookupHostGeo(cfg, rec.Host, rec.Remarks, logger)
}

func runConfigChecks(cfg Config, rec Record, proxyURL *url.URL, logger Logger) (TestResult, error) {
	pingTimeout := effectiveProbeTimeout(cfg)
	securityTimeout := effectiveSecurityProbeTimeout(cfg)
	type pingResult struct {
		latency int
		err     error
	}
	type speedResult struct {
		speed float64
		err   error
	}
	type securityResult struct {
		findings []ActiveFinding
		critical bool
		err      error
	}
	type geoResult struct {
		geo GeoInfo
		err error
	}
	pingCh := make(chan pingResult, 1)
	speedCh := make(chan speedResult, 1)
	securityCh := make(chan securityResult, 1)
	geoCh := make(chan geoResult, 1)
	go func() {
		latency, err := probeURLs(cfg.Probes.PingURLs, pingTimeout, proxyURL, cfg.Probes.UseAllProbeURLs, cfg.Probes.FallbackProbeURLs)
		pingCh <- pingResult{latency: latency, err: err}
	}()
	pingRes := <-pingCh
	if pingRes.err != nil {
		return TestResult{
			PingOK:                  false,
			LatencyMS:               -1,
			SpeedMBps:               0,
			Geo:                     GeoInfo{},
			SecurityFindings:        nil,
			CriticalSecurityFailure: false,
		}, pingRes.err
	}
	go func() {
		speed, err := speedTest(cfg.Probes.SpeedURLs, pingTimeout, proxyURL, cfg.Probes.SpeedTestBytes, cfg.Probes.UseAllProbeURLs, cfg.Probes.FallbackProbeURLs)
		speedCh <- speedResult{speed: speed, err: err}
	}()
	go func() {
		findings, critical, err := runActiveSecurityProbes(cfg.Probes.SecurityProbes, securityTimeout, proxyURL)
		securityCh <- securityResult{findings: findings, critical: critical, err: err}
	}()
	go func() {
		geo, err := fastGeoForRecord(cfg, rec, proxyURL, logger)
		geoCh <- geoResult{geo: geo, err: err}
	}()
	speedRes := <-speedCh
	securityRes := <-securityCh
	geoRes := <-geoCh
	if securityRes.err != nil {
		logger.file("security", "active security probes partial failure endpoint=%s err=%v", rec.EndpointKey, securityRes.err)
	}
	if geoRes.err != nil {
		logger.file("geo", "geo lookup partial failure endpoint=%s err=%v", rec.EndpointKey, geoRes.err)
	}
	if speedRes.err != nil {
		logger.file("testing", "speed test partial failure endpoint=%s err=%v", rec.EndpointKey, speedRes.err)
	}
	return TestResult{
		PingOK:                  true,
		LatencyMS:               pingRes.latency,
		SpeedMBps:               speedRes.speed,
		Geo:                     geoRes.geo,
		SecurityFindings:        securityRes.findings,
		CriticalSecurityFailure: securityRes.critical,
	}, nil
}

func prepareXrayJSONConfig(cfg map[string]any, localPort int) map[string]any {
	cfg["log"] = map[string]any{"loglevel": "warning"}
	injected := map[string]any{
		"port":     localPort,
		"listen":   "127.0.0.1",
		"protocol": "http",
		"settings": map[string]any{},
	}
	if existing, ok := cfg["inbounds"].([]any); ok && len(existing) > 0 {
		cfg["inbounds"] = append([]any{injected}, existing...)
	} else if existing := asMap(cfg["inbound"]); len(existing) > 0 {
		cfg["inbounds"] = []any{injected, existing}
		delete(cfg, "inbound")
	} else {
		cfg["inbounds"] = []any{injected}
	}
	if _, ok := cfg["outbounds"]; !ok {
		cfg["outbounds"] = []any{map[string]any{"protocol": "freedom", "tag": "direct"}}
	}
	return cfg
}

func prepareSingBoxJSONConfig(cfg map[string]any, localPort int) map[string]any {
	cfg["log"] = map[string]any{"level": "warn"}
	injected := map[string]any{
		"type":        "http",
		"tag":         "http-in",
		"listen":      "127.0.0.1",
		"listen_port": localPort,
	}
	if existing, ok := cfg["inbounds"].([]any); ok && len(existing) > 0 {
		cfg["inbounds"] = append([]any{injected}, existing...)
	} else if existing := asMap(cfg["inbound"]); len(existing) > 0 {
		cfg["inbounds"] = []any{injected, existing}
		delete(cfg, "inbound")
	} else {
		cfg["inbounds"] = []any{injected}
	}
	if _, ok := cfg["outbounds"]; !ok {
		cfg["outbounds"] = []any{map[string]any{"type": "direct", "tag": "direct"}}
	}
	return cfg
}

func buildXrayConfig(localPort int, rec Record) (map[string]any, error) {
	details := rec.Details
	params := asMap(details["params"])
	outbound := map[string]any{
		"protocol":       rec.Protocol,
		"settings":       map[string]any{},
		"streamSettings": map[string]any{},
		"tag":            "proxy",
	}
	switch rec.Protocol {
	case "vmess":
		outbound["settings"] = map[string]any{
			"vnext": []any{
				map[string]any{
					"address": rec.Host,
					"port":    rec.Port,
					"users": []any{
						map[string]any{
							"id":       asString(details["id"]),
							"alterId":  intFromAny(details["aid"]),
							"security": "auto",
						},
					},
				},
			},
		}
		outbound["streamSettings"] = buildXrayStreamSettings(rec.Protocol, rec.Host, details, params)
	case "vless":
		outbound["settings"] = map[string]any{
			"vnext": []any{
				map[string]any{
					"address": rec.Host,
					"port":    rec.Port,
					"users": []any{
						map[string]any{
							"id":         asString(details["auth"]),
							"encryption": "none",
							"level":      0,
							"flow":       asString(params["flow"]),
						},
					},
				},
			},
		}
		outbound["streamSettings"] = buildXrayStreamSettings(rec.Protocol, rec.Host, details, params)
	case "trojan":
		outbound["settings"] = map[string]any{
			"servers": []any{
				map[string]any{"address": rec.Host, "port": rec.Port, "password": asString(details["auth"])},
			},
		}
		outbound["streamSettings"] = buildXrayStreamSettings(rec.Protocol, rec.Host, details, params)
	case "ss":
		outbound["protocol"] = "shadowsocks"
		outbound["settings"] = map[string]any{
			"servers": []any{
				map[string]any{"address": rec.Host, "port": rec.Port, "method": asString(details["method"]), "password": asString(details["password"])},
			},
		}
	case "socks":
		outbound["protocol"] = "socks"
		server := map[string]any{"address": rec.Host, "port": rec.Port}
		user, pass := splitAuthPair(firstNonEmpty(asString(details["auth"]), firstNonEmpty(asString(details["user"]), "")+":"+asString(details["password"])))
		if user != "" || pass != "" {
			server["users"] = []any{map[string]any{"user": user, "pass": pass}}
		}
		if version := firstNonEmpty(asString(details["version"]), asString(params["version"])); version != "" {
			server["version"] = version
		}
		outbound["settings"] = map[string]any{"servers": []any{server}}
	case "http":
		outbound["protocol"] = "http"
		server := map[string]any{"address": rec.Host, "port": rec.Port}
		user, pass := splitAuthPair(asString(details["auth"]))
		if user != "" || pass != "" {
			server["users"] = []any{map[string]any{"user": user, "pass": pass}}
		}
		outbound["settings"] = map[string]any{"servers": []any{server}}
		if strings.EqualFold(asString(params["tls"]), "true") || strings.EqualFold(asString(params["security"]), "tls") {
			outbound["streamSettings"] = buildXrayStreamSettings(rec.Protocol, rec.Host, details, params)
		}
	case "tor":
		outbound["protocol"] = "socks"
		outbound["settings"] = map[string]any{
			"servers": []any{
				map[string]any{"address": rec.Host, "port": rec.Port, "version": "5"},
			},
		}
	case "direct":
		outbound = map[string]any{"protocol": "freedom", "tag": "proxy"}
	case "block":
		outbound = map[string]any{"protocol": "blackhole", "tag": "proxy"}
	default:
		return nil, unsupportedError{fmt.Sprintf("xray builder missing for %s", rec.Protocol)}
	}
	return map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"dns": map[string]any{"servers": []any{"1.1.1.1", "8.8.8.8"}},
		"inbounds": []any{
			map[string]any{
				"port":     localPort,
				"listen":   "127.0.0.1",
				"protocol": "http",
				"settings": map[string]any{},
			},
		},
		"outbounds": []any{
			outbound,
			map[string]any{"protocol": "freedom", "tag": "direct"},
		},
		"routing": map[string]any{
			"domainStrategy": "IPIfNonMatch",
			"rules": []any{
				map[string]any{"type": "field", "port": 53, "outboundTag": "proxy"},
			},
		},
	}, nil
}

func buildXrayStreamSettings(protocol, host string, details map[string]any, params map[string]any) map[string]any {
	network := firstNonEmpty(asString(params["type"]), asString(details["net"]), "tcp")
	security := firstNonEmpty(asString(params["security"]), asString(details["tls"]), "none")
	stream := map[string]any{
		"network":  normalizeTransport(network),
		"security": normalizeStreamSecurity(security),
	}
	serverName := firstNonEmpty(asString(params["sni"]), asString(details["sni"]), asString(params["host"]), asString(details["host"]), host)
	fingerprint := firstNonEmpty(asString(params["fp"]), asString(params["fingerprint"]), asString(params["utls"]), asString(params["uTLS"]), asString(details["fp"]), "chrome")
	if sec := normalizeStreamSecurity(security); sec == "tls" || sec == "reality" || sec == "xtls" {
		tlsSettings := map[string]any{
			"serverName":    serverName,
			"allowInsecure": false,
			"fingerprint":   fingerprint,
		}
		if alpn := splitCSVToAny(firstNonEmpty(asString(params["alpn"]), asString(details["alpn"]))); len(alpn) > 0 {
			tlsSettings["alpn"] = alpn
		}
		stream["tlsSettings"] = tlsSettings
	}
	if normalizeStreamSecurity(security) == "xtls" {
		stream["xtlsSettings"] = map[string]any{
			"serverName":    serverName,
			"allowInsecure": false,
			"fingerprint":   fingerprint,
		}
	}
	if normalizeStreamSecurity(security) == "reality" {
		stream["realitySettings"] = map[string]any{
			"serverName":  serverName,
			"publicKey":   asString(params["pbk"]),
			"shortId":     asString(params["sid"]),
			"fingerprint": fingerprint,
			"spiderX":     asString(params["spx"]),
		}
	}
	switch normalizeTransport(network) {
	case "ws":
		stream["wsSettings"] = map[string]any{
			"path":    fallback(firstNonEmpty(asString(params["path"]), asString(details["path"])), "/"),
			"headers": map[string]any{"Host": firstNonEmpty(asString(params["host"]), asString(details["host"]), host)},
		}
	case "httpupgrade":
		stream["httpupgradeSettings"] = map[string]any{
			"path": fallback(asString(params["path"]), "/"),
			"host": firstNonEmpty(asString(params["host"]), host),
		}
	case "grpc":
		stream["grpcSettings"] = map[string]any{
			"serviceName":          firstNonEmpty(asString(params["serviceName"]), asString(params["path"]), asString(details["path"])),
			"multiMode":            strings.EqualFold(asString(params["mode"]), "multi"),
			"idle_timeout":         60,
			"health_check_timeout": 20,
		}
	case "http", "h2":
		stream["httpSettings"] = map[string]any{
			"path": fallback(asString(params["path"]), "/"),
			"host": splitCSVToAny(firstNonEmpty(asString(params["host"]), host)),
		}
	case "kcp":
		stream["kcpSettings"] = map[string]any{
			"seed":   asString(params["seed"]),
			"header": map[string]any{"type": firstNonEmpty(asString(params["headerType"]), "none")},
		}
	case "quic":
		stream["quicSettings"] = map[string]any{
			"security": firstNonEmpty(asString(params["quicSecurity"]), "none"),
			"key":      asString(params["key"]),
			"header":   map[string]any{"type": firstNonEmpty(asString(params["headerType"]), "none")},
		}
	case "xhttp":
		stream["xhttpSettings"] = map[string]any{
			"path": fallback(asString(params["path"]), "/"),
			"mode": firstNonEmpty(asString(params["mode"]), "auto"),
			"host": firstNonEmpty(asString(params["host"]), host),
		}
	case "ds", "uds":
		stream["dsSettings"] = map[string]any{
			"path": asString(params["path"]),
		}
	case "tcp":
		if headerType := asString(params["headerType"]); headerType != "" {
			stream["tcpSettings"] = map[string]any{"header": map[string]any{"type": headerType}}
		}
	}
	_ = protocol
	return stream
}

func buildSingBoxConfig(localPort int, rec Record) (map[string]any, error) {
	details := rec.Details
	params := asMap(details["params"])
	outbound := map[string]any{
		"type": "direct",
		"tag":  "proxy",
	}
	switch rec.Protocol {
	case "hysteria2":
		outbound = map[string]any{
			"type":        "hysteria2",
			"tag":         "proxy",
			"server":      rec.Host,
			"server_port": rec.Port,
			"password":    firstNonEmpty(asString(details["auth"]), asString(params["obfs-password"])),
			"up_mbps":     100,
			"down_mbps":   100,
			"tls": map[string]any{
				"enabled":     true,
				"server_name": firstNonEmpty(asString(params["sni"]), rec.Host),
				"insecure":    false,
			},
		}
		if obfs := asString(params["obfs"]); obfs != "" {
			outbound["obfs"] = map[string]any{"type": obfs, "password": asString(params["obfs-password"])}
		}
	case "hysteria":
		outbound = map[string]any{
			"type":        "hysteria",
			"tag":         "proxy",
			"server":      rec.Host,
			"server_port": rec.Port,
			"auth_str":    asString(details["auth"]),
			"up_mbps":     100,
			"down_mbps":   100,
			"tls": map[string]any{
				"enabled":     true,
				"server_name": firstNonEmpty(asString(params["sni"]), rec.Host),
				"insecure":    false,
			},
		}
	case "tuic":
		uuid, password := splitAuthPair(asString(details["auth"]))
		if uuid == "" {
			uuid = asString(details["auth"])
		}
		outbound = map[string]any{
			"type":        "tuic",
			"tag":         "proxy",
			"server":      rec.Host,
			"server_port": rec.Port,
			"uuid":        uuid,
			"password":    firstNonEmpty(password, asString(params["password"])),
			"tls": map[string]any{
				"enabled":     true,
				"server_name": firstNonEmpty(asString(params["sni"]), rec.Host),
				"insecure":    false,
			},
		}
		if val := asString(params["congestion_control"]); val != "" {
			outbound["congestion_control"] = val
		}
	case "ssr":
		outbound = map[string]any{
			"type":        "shadowsocks",
			"tag":         "proxy",
			"server":      rec.Host,
			"server_port": rec.Port,
			"method":      asString(details["method"]),
			"password":    asString(details["password"]),
		}
	case "wireguard":
		outbound = map[string]any{
			"type":        "wireguard",
			"tag":         "proxy",
			"server":      rec.Host,
			"server_port": rec.Port,
			"private_key": asString(details["private_key"]),
			"peer_public_key": firstNonEmpty(
				asString(params["peer_public_key"]),
				asString(params["public_key"]),
				asString(details["peer_public_key"]),
			),
			"local_address": []any{
				firstNonEmpty(asString(params["ip"]), asString(params["address"]), "10.0.0.2/32"),
			},
		}
	case "anytls":
		outbound = map[string]any{
			"type":        "anytls",
			"tag":         "proxy",
			"server":      rec.Host,
			"server_port": rec.Port,
			"password":    firstNonEmpty(asString(details["password"]), asString(details["auth"])),
			"tls": map[string]any{
				"enabled":     true,
				"server_name": firstNonEmpty(asString(params["sni"]), rec.Host),
				"insecure":    false,
			},
		}
	case "shadowtls":
		version := intFromAny(params["version"])
		if version == 0 {
			version = 3
		}
		outbound = map[string]any{
			"type":        "shadowtls",
			"tag":         "proxy",
			"server":      rec.Host,
			"server_port": rec.Port,
			"version":     version,
			"password":    firstNonEmpty(asString(details["password"]), asString(details["auth"])),
			"tls": map[string]any{
				"enabled":     true,
				"server_name": firstNonEmpty(asString(params["sni"]), rec.Host),
				"insecure":    false,
			},
		}
	case "ssh":
		outbound = map[string]any{
			"type":        "ssh",
			"tag":         "proxy",
			"server":      rec.Host,
			"server_port": rec.Port,
			"user":        asString(details["user"]),
			"password":    asString(details["password"]),
		}
	case "naive":
		outbound = map[string]any{
			"type":        "naive",
			"tag":         "proxy",
			"server":      rec.Host,
			"server_port": rec.Port,
			"username":    firstNonEmpty(asString(details["username"]), firstSegment(asString(details["auth"]), ":")),
			"password":    firstNonEmpty(asString(details["password"]), secondSegment(asString(details["auth"]), ":")),
			"tls": map[string]any{
				"enabled":     true,
				"server_name": firstNonEmpty(asString(params["sni"]), rec.Host),
				"insecure":    false,
			},
		}
	default:
		return nil, unsupportedError{fmt.Sprintf("sing-box builder missing for %s", rec.Protocol)}
	}
	return map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{
			map[string]any{
				"type":        "http",
				"tag":         "http-in",
				"listen":      "127.0.0.1",
				"listen_port": localPort,
			},
		},
		"outbounds": []any{
			outbound,
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{"final": "proxy"},
	}, nil
}

func buildXrayValidationConfig(rec Record) (map[string]any, error) {
	params := asMap(rec.Details["params"])
	base := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}},
	}
	switch rec.Protocol {
	case "dns":
		base["outbounds"] = []any{
			map[string]any{"protocol": "dns", "tag": "proxy", "settings": map[string]any{}},
			map[string]any{"protocol": "freedom", "tag": "direct"},
		}
	case "dokodemo-door":
		address := firstNonEmpty(asString(params["target"]), asString(params["address"]), rec.Host, "1.1.1.1")
		port := validationPort(intFromAny(firstNonEmptyAny(params["target_port"], params["port"])), validationPort(rec.Port, 80))
		base["inbounds"] = []any{
			map[string]any{
				"tag":      "target-in",
				"listen":   "127.0.0.1",
				"port":     validationPort(rec.Port, 1080),
				"protocol": "dokodemo-door",
				"settings": map[string]any{
					"address": address,
					"port":    port,
					"network": firstNonEmpty(asString(params["network"]), "tcp,udp"),
				},
			},
		}
	default:
		return nil, unsupportedError{fmt.Sprintf("xray validation builder missing for %s", rec.Protocol)}
	}
	return base, nil
}

func buildSingBoxValidationConfig(rec Record) (map[string]any, error) {
	params := asMap(rec.Details["params"])
	config := map[string]any{
		"log": map[string]any{"level": "warn"},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "block"},
		},
	}
	switch rec.Protocol {
	case "block":
		config["outbounds"] = append([]any{map[string]any{"type": "block", "tag": "proxy"}}, config["outbounds"].([]any)...)
		config["route"] = map[string]any{"final": "proxy"}
	case "selector", "urltest":
		tags := splitCSV(asString(params["outbounds"]))
		if len(tags) == 0 {
			tags = []string{"candidate-a", "candidate-b"}
		}
		extraOutbounds := make([]any, 0, len(tags))
		for _, tag := range tags {
			extraOutbounds = append(extraOutbounds, map[string]any{"type": "direct", "tag": tag})
		}
		selector := map[string]any{
			"type":      rec.Protocol,
			"tag":       "proxy",
			"outbounds": stringsToAny(tags),
		}
		if rec.Protocol == "selector" {
			selector["default"] = tags[0]
		} else {
			selector["url"] = "https://www.gstatic.com/generate_204"
			selector["interval"] = "10m"
			selector["idle_timeout"] = "30s"
		}
		config["outbounds"] = append([]any{selector}, append(extraOutbounds, config["outbounds"].([]any)...)...)
		config["route"] = map[string]any{"final": "proxy"}
	case "mixed":
		config["inbounds"] = []any{
			map[string]any{
				"type":        "mixed",
				"tag":         "target-in",
				"listen":      "127.0.0.1",
				"listen_port": validationPort(rec.Port, 1080),
			},
		}
	case "tun":
		config["inbounds"] = []any{
			map[string]any{
				"type":           "tun",
				"tag":            "target-in",
				"interface_name": "sb-validate",
				"inet4_address":  []any{"172.19.0.1/30"},
				"auto_route":     false,
				"strict_route":   false,
				"mtu":            1400,
			},
		}
	case "tap":
		config["inbounds"] = []any{
			map[string]any{
				"type":           "tap",
				"tag":            "target-in",
				"interface_name": "sb-validate-tap",
				"inet4_address":  []any{"172.19.0.1/30"},
				"auto_route":     false,
				"strict_route":   false,
			},
		}
	case "tproxy":
		config["inbounds"] = []any{
			map[string]any{
				"type":        rec.Protocol,
				"tag":         "target-in",
				"listen":      "127.0.0.1",
				"listen_port": validationPort(rec.Port, 1080),
				"network":     firstNonEmpty(asString(params["network"]), "tcp"),
			},
		}
	case "redirect":
		config["inbounds"] = []any{
			map[string]any{
				"type":        "redirect",
				"tag":         "target-in",
				"listen":      "127.0.0.1",
				"listen_port": validationPort(rec.Port, 1080),
			},
		}
	case "shadowtls":
		version := intFromAny(params["version"])
		if version == 0 {
			version = 3
		}
		config["outbounds"] = append([]any{
			map[string]any{
				"type":        "shadowtls",
				"tag":         "proxy",
				"server":      firstNonEmpty(rec.Host, "example.com"),
				"server_port": validationPort(rec.Port, 443),
				"version":     version,
				"password":    firstNonEmpty(asString(rec.Details["password"]), asString(rec.Details["auth"]), "shadowtls-pass"),
				"tls": map[string]any{
					"enabled":     true,
					"server_name": firstNonEmpty(asString(params["sni"]), rec.Host, "example.com"),
					"insecure":    false,
				},
			},
		}, config["outbounds"].([]any)...)
		config["route"] = map[string]any{"final": "proxy"}
	case "wireguard":
		config["outbounds"] = append([]any{
			map[string]any{
				"type":            "wireguard",
				"tag":             "proxy",
				"server":          firstNonEmpty(rec.Host, "127.0.0.1"),
				"server_port":     validationPort(rec.Port, 51820),
				"private_key":     firstNonEmpty(asString(rec.Details["private_key"]), placeholderWireGuardKey()),
				"peer_public_key": firstNonEmpty(asString(params["peer_public_key"]), asString(params["public_key"]), asString(rec.Details["peer_public_key"]), placeholderWireGuardKey()),
				"local_address":   []any{firstNonEmpty(asString(params["ip"]), asString(params["address"]), "10.0.0.2/32")},
			},
		}, config["outbounds"].([]any)...)
		config["route"] = map[string]any{"final": "proxy"}
	case "tailscale":
		config["outbounds"] = append([]any{
			map[string]any{
				"type": "tailscale",
				"tag":  "proxy",
			},
		}, config["outbounds"].([]any)...)
		config["route"] = map[string]any{"final": "proxy"}
	case "juicity":
		config["outbounds"] = append([]any{
			map[string]any{
				"type":        "juicity",
				"tag":         "proxy",
				"server":      firstNonEmpty(rec.Host, "example.com"),
				"server_port": validationPort(rec.Port, 443),
				"uuid":        firstNonEmpty(asString(rec.Details["auth"]), "00000000-0000-0000-0000-000000000000"),
				"password":    firstNonEmpty(asString(params["password"]), "juicity-pass"),
				"tls": map[string]any{
					"enabled":     true,
					"server_name": firstNonEmpty(asString(params["sni"]), rec.Host, "example.com"),
					"insecure":    false,
				},
			},
		}, config["outbounds"].([]any)...)
		config["route"] = map[string]any{"final": "proxy"}
	default:
		return nil, unsupportedError{fmt.Sprintf("sing-box validation builder missing for %s", rec.Protocol)}
	}
	return config, nil
}

func validationPort(port, fallback int) int {
	switch {
	case port > 0 && port <= 65535:
		return port
	case fallback > 0 && fallback <= 65535:
		return fallback
	default:
		return 1080
	}
}

func placeholderWireGuardKey() string {
	return strings.Repeat("A", 43) + "="
}

func stringsToAny(items []string) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			out = append(out, item)
		}
	}
	return out
}

func probeURLs(urls []string, timeout time.Duration, proxyURL *url.URL, useAll, allowFallback bool) (int, error) {
	client := newHTTPClientDuration(timeout, proxyURL)
	var lastErr error
	for _, probe := range selectProbeAttempts(urls, useAll, allowFallback) {
		start := time.Now()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, probe, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			return int(time.Since(start).Milliseconds()), nil
		}
		lastErr = fmt.Errorf("status %d", resp.StatusCode)
	}
	if lastErr == nil {
		lastErr = errors.New("no ping url configured")
	}
	return -1, lastErr
}

func speedTest(urls []string, timeout time.Duration, proxyURL *url.URL, limitBytes int64, useAll, allowFallback bool) (float64, error) {
	client := newHTTPClientDuration(timeout, proxyURL)
	var lastErr error
	if limitBytes <= 0 {
		limitBytes = 64 * 1024
	}
	for _, probe := range selectProbeAttempts(urls, useAll, allowFallback) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, probe, nil)
		if err != nil {
			lastErr = err
			continue
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, limitBytes))
		resp.Body.Close()
		if err != nil && n == 0 {
			lastErr = err
			continue
		}
		seconds := math.Max(time.Since(start).Seconds(), 0.001)
		mbps := (float64(n) / 1048576) / seconds
		if mbps < 0 {
			mbps = 0
		}
		return math.Round(mbps*10000) / 10000, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no speed url configured")
	}
	return 0, lastErr
}

func runActiveSecurityProbes(probes []ActiveSecurityProbe, timeout time.Duration, proxyURL *url.URL) ([]ActiveFinding, bool, error) {
	if len(probes) == 0 {
		return nil, false, nil
	}
	findings := make([]ActiveFinding, 0, 8)
	observations := make([]probeObservation, 0, len(probes))
	critical := false
	var lastErr error
	type probeRun struct {
		observation probeObservation
		findings    []ActiveFinding
		err         error
	}
	results := make([]probeRun, len(probes))
	var wg sync.WaitGroup
	for idx, probe := range probes {
		wg.Add(1)
		go func(index int, current ActiveSecurityProbe) {
			defer wg.Done()
			observation, probeFindings, err := runSingleSecurityProbe(current, timeout, proxyURL)
			results[index] = probeRun{observation: observation, findings: probeFindings, err: err}
		}(idx, probe)
	}
	wg.Wait()
	for _, result := range results {
		if result.err != nil {
			lastErr = result.err
		}
		if result.observation.Probe.Name != "" || result.observation.Probe.URL != "" {
			observations = append(observations, result.observation)
		}
		for _, finding := range result.findings {
			findings = append(findings, finding)
			if finding.Critical {
				critical = true
			}
		}
	}
	groupFindings := compareProbeObservations(observations)
	for _, finding := range groupFindings {
		findings = append(findings, finding)
		if finding.Critical {
			critical = true
		}
	}
	return findings, critical, lastErr
}

func runSingleSecurityProbe(probe ActiveSecurityProbe, timeout time.Duration, proxyURL *url.URL) (probeObservation, []ActiveFinding, error) {
	client := newHTTPClientDuration(timeout, proxyURL)
	originURL, _ := url.Parse(probe.URL)
	redirectCount := 0
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		redirectCount = len(via)
		if probe.RejectRedirect {
			return http.ErrUseLastResponse
		}
		maxRedirects := probe.MaxRedirects
		if maxRedirects <= 0 {
			maxRedirects = 5
		}
		if len(via) >= maxRedirects {
			return errors.New("too many redirects")
		}
		return nil
	}
	method := strings.ToUpper(strings.TrimSpace(probe.Method))
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(context.Background(), method, probe.URL, nil)
	if err != nil {
		return probeObservation{}, nil, err
	}
	for key, value := range probe.Headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return probeObservation{}, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBytes(probe)))
	if err != nil {
		return probeObservation{}, nil, err
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	bodyLower := strings.ToLower(string(body))
	findings := make([]ActiveFinding, 0, 8)
	observation := probeObservation{
		Probe:         probe,
		Status:        resp.StatusCode,
		ContentType:   contentType,
		BodyHash:      sha256Hex(body),
		BodyLen:       int64(len(body)),
		RedirectCount: redirectCount,
		FinalHost:     resp.Request.URL.Hostname(),
		TLSVersion:    tlsVersionString(resp),
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		observation.TLSExpiresAt = resp.TLS.PeerCertificates[0].NotAfter
	}
	if status, answers, ok := inspectJSONProbeBody(body); ok {
		observation.JSONStatus = &status
		observation.JSONAnswers = answers
	}
	addFinding := func(message string, critical bool, penalty int) {
		findings = append(findings, ActiveFinding{
			Message:  message,
			Critical: critical,
			Penalty:  probePenalty(probe, penalty),
		})
	}
	if probe.ExpectStatus > 0 && resp.StatusCode != probe.ExpectStatus {
		addFinding(fmt.Sprintf("%s status expected %d got %d", probeLabel(probe), probe.ExpectStatus, resp.StatusCode), probe.Critical, 80)
	}
	if probe.ExpectStatus == http.StatusNoContent && len(body) > 0 {
		addFinding(fmt.Sprintf("%s returned body on 204 response", probeLabel(probe)), true, 170)
	}
	if probe.RejectRedirect && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		addFinding(fmt.Sprintf("%s unexpected redirect", probeLabel(probe)), true, 120)
	}
	if originURL != nil && strings.EqualFold(originURL.Scheme, "https") && !strings.EqualFold(resp.Request.URL.Scheme, "https") {
		addFinding(fmt.Sprintf("%s downgraded from https to %s", probeLabel(probe), resp.Request.URL.Scheme), true, 170)
	}
	if len(probe.AllowedRedirectHosts) > 0 && redirectCount > 0 && !containsFold(probe.AllowedRedirectHosts, observation.FinalHost) {
		addFinding(fmt.Sprintf("%s redirected to disallowed host %s", probeLabel(probe), observation.FinalHost), true, 120)
	}
	if probe.ExpectContentType != "" && !strings.Contains(contentType, strings.ToLower(probe.ExpectContentType)) {
		addFinding(fmt.Sprintf("%s content-type mismatch: %s", probeLabel(probe), contentType), probe.Critical, 70)
	}
	if probe.ExpectMinBytes > 0 && int64(len(body)) < probe.ExpectMinBytes {
		addFinding(fmt.Sprintf("%s body too small: %d", probeLabel(probe), len(body)), probe.Critical, 60)
	}
	if probe.ExpectMaxBytes >= 0 && int64(len(body)) > probe.ExpectMaxBytes {
		addFinding(fmt.Sprintf("%s body too large: %d", probeLabel(probe), len(body)), probe.Critical, 60)
	}
	for _, want := range probe.ExpectContains {
		if !strings.Contains(bodyLower, strings.ToLower(want)) {
			addFinding(fmt.Sprintf("%s missing marker %q", probeLabel(probe), want), probe.Critical, 80)
		}
	}
	for _, reject := range probe.RejectContains {
		if strings.Contains(bodyLower, strings.ToLower(reject)) {
			addFinding(fmt.Sprintf("%s contains rejected marker %q", probeLabel(probe), reject), true, 140)
		}
	}
	if looksLikeInterceptionHTML(contentType, bodyLower) {
		addFinding(fmt.Sprintf("%s looks like html injection/captive portal", probeLabel(probe)), true, 180)
	}
	if hasSuspiciousIntermediaryHeaders(resp.Header) {
		addFinding(fmt.Sprintf("%s exposed interception headers", probeLabel(probe)), true, 130)
	}
	if probe.ExpectSHA256 != "" && !strings.EqualFold(probe.ExpectSHA256, observation.BodyHash) {
		addFinding(fmt.Sprintf("%s body hash mismatch", probeLabel(probe)), probe.Critical, 100)
	}
	for _, rejectHash := range probe.RejectSHA256 {
		if strings.EqualFold(rejectHash, observation.BodyHash) {
			addFinding(fmt.Sprintf("%s matched rejected body hash", probeLabel(probe)), true, 150)
		}
	}
	for key, expected := range probe.ExpectHeaders {
		if !strings.Contains(strings.ToLower(resp.Header.Get(key)), strings.ToLower(expected)) {
			addFinding(fmt.Sprintf("%s missing expected header %s", probeLabel(probe), key), probe.Critical, 50)
		}
	}
	for key, banned := range probe.RejectHeaders {
		if strings.Contains(strings.ToLower(resp.Header.Get(key)), strings.ToLower(banned)) {
			addFinding(fmt.Sprintf("%s contains rejected header %s", probeLabel(probe), key), true, 100)
		}
	}
	if resp.Request.URL.Scheme == "https" {
		if resp.TLS == nil {
			addFinding(fmt.Sprintf("%s missing tls state", probeLabel(probe)), true, 150)
		} else {
			if versionPenalty := tlsVersionPenalty(observation.TLSVersion); versionPenalty > 0 {
				addFinding(fmt.Sprintf("%s weak tls version %s", probeLabel(probe), observation.TLSVersion), true, versionPenalty)
			}
			if !observation.TLSExpiresAt.IsZero() && time.Until(observation.TLSExpiresAt) < 7*24*time.Hour {
				addFinding(fmt.Sprintf("%s certificate expires too soon", probeLabel(probe)), false, 50)
			}
		}
	}
	if observation.JSONStatus != nil && *observation.JSONStatus != 0 {
		addFinding(fmt.Sprintf("%s dns/json status=%d", probeLabel(probe), *observation.JSONStatus), true, 140)
	}
	if observation.JSONStatus != nil && observation.JSONAnswers == 0 {
		addFinding(fmt.Sprintf("%s dns/json returned zero answers", probeLabel(probe)), true, 140)
	}
	return observation, findings, nil
}

func maxProbeBytes(probe ActiveSecurityProbe) int64 {
	if probe.ExpectMaxBytes > 0 {
		return maxInt64(probe.ExpectMaxBytes+1024, 4096)
	}
	return 8192
}

func looksLikeInterceptionHTML(contentType, bodyLower string) bool {
	if strings.Contains(contentType, "text/html") {
		return true
	}
	markers := []string{
		"<!doctype html",
		"<html",
		"<head",
		"<body",
		"http-equiv=\"refresh\"",
		"http-equiv='refresh'",
		"window.location",
		"document.location",
		"captcha",
		"access denied",
		"blocked by",
		"fortigate",
		"mikrotik",
		"openresty",
		"nginx error",
	}
	for _, marker := range markers {
		if strings.Contains(bodyLower, marker) {
			return true
		}
	}
	return false
}

func hasSuspiciousIntermediaryHeaders(header http.Header) bool {
	suspectPairs := map[string][]string{
		"Via":                        {"squid", "mikrotik", "fortigate"},
		"X-BlueCoat-Via":             {""},
		"X-Squid-Error":              {""},
		"Proxy-Connection":           {""},
		"X-Forwarded-For":            {""},
		"X-Mitmproxy-Blocked-Reason": {""},
	}
	for key, needles := range suspectPairs {
		value := strings.ToLower(strings.TrimSpace(header.Get(key)))
		if value == "" {
			continue
		}
		for _, needle := range needles {
			if needle == "" || strings.Contains(value, needle) {
				return true
			}
		}
	}
	return false
}

func compareProbeObservations(observations []probeObservation) []ActiveFinding {
	grouped := make(map[string][]probeObservation)
	for _, observation := range observations {
		group := strings.TrimSpace(observation.Probe.CompareGroup)
		if group == "" {
			continue
		}
		grouped[group] = append(grouped[group], observation)
	}
	findings := make([]ActiveFinding, 0, 6)
	for group, items := range grouped {
		if len(items) < 2 {
			continue
		}
		if finding, ok := compareGroupBodies(group, items); ok {
			findings = append(findings, finding)
		}
		if strings.Contains(strings.ToLower(group), "dns") {
			if finding, ok := compareDNSProbeGroup(group, items); ok {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

func compareGroupBodies(group string, items []probeObservation) (ActiveFinding, bool) {
	hashToHosts := make(map[string][]string)
	for _, item := range items {
		if item.BodyLen < 128 {
			continue
		}
		if strings.Contains(item.ContentType, "text/html") || strings.Contains(item.ContentType, "text/plain") {
			hashToHosts[item.BodyHash] = append(hashToHosts[item.BodyHash], item.FinalHost)
		}
	}
	for hash, hosts := range hashToHosts {
		if len(hosts) >= 2 && uniqueCount(hosts) >= 2 {
			return ActiveFinding{
				Message:  fmt.Sprintf("compare-group %s returned same body hash %s across multiple hosts", group, hash[:16]),
				Critical: true,
				Penalty:  160,
			}, true
		}
	}
	return ActiveFinding{}, false
}

func compareDNSProbeGroup(group string, items []probeObservation) (ActiveFinding, bool) {
	var statuses []int
	var answerCounts []int
	for _, item := range items {
		if item.JSONStatus == nil {
			return ActiveFinding{
				Message:  fmt.Sprintf("dns compare-group %s did not return parseable json", group),
				Critical: true,
				Penalty:  120,
			}, true
		}
		statuses = append(statuses, *item.JSONStatus)
		answerCounts = append(answerCounts, item.JSONAnswers)
	}
	if !allSameInt(statuses) {
		return ActiveFinding{
			Message:  fmt.Sprintf("dns compare-group %s returned inconsistent status codes", group),
			Critical: true,
			Penalty:  120,
		}, true
	}
	for _, count := range answerCounts {
		if count == 0 {
			return ActiveFinding{
				Message:  fmt.Sprintf("dns compare-group %s returned zero answers", group),
				Critical: true,
				Penalty:  120,
			}, true
		}
	}
	return ActiveFinding{}, false
}

func lookupHostGeo(cfg Config, host, remarks string, logger Logger) (GeoInfo, error) {
	host = normalizeHost(host)
	if host == "" {
		return fallbackGeoFromRemarks(remarks), errors.New("empty host")
	}
	if isPrivateHost(host) {
		return GeoInfo{Country: "Internal Network", CountryCode: "LAN", Flag: "🏠"}, nil
	}
	ip := host
	if net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			geo := fallbackGeoFromRemarks(remarks)
			if geo.Country != "" {
				return geo, nil
			}
			return GeoInfo{Country: "Unknown", CountryCode: "UN", Flag: "🌐"}, err
		}
		ip = pickIP(ips)
	}
	if geo, err := lookupGeoByIP(cfg, ip); err == nil && geo.CountryCode != "" {
		return geo, nil
	}
	logger.file("geo", "fallback geo for host=%s ip=%s", host, ip)
	geo := fallbackGeoFromRemarks(remarks)
	if geo.CountryCode != "" {
		return geo, nil
	}
	return fallbackGeoFromHost(host), nil
}

func lookupGeoByIP(cfg Config, ip string) (GeoInfo, error) {
	if geo, err := lookupLocalGeoCity(cfg.Probes.LocalGeoCityDB, ip); err == nil && geo.CountryCode != "" {
		return geo, nil
	}
	if geo, err := lookupLocalGeo(cfg.Probes.LocalGeoDB, ip); err == nil && geo.CountryCode != "" {
		return geo, nil
	}
	geo, err := geoLookup(cfg.Probes.GeoLookupURLs, ip, nil, cfg.Probes.TimeoutSeconds, cfg.Probes.UseAllProbeURLs, cfg.Probes.FallbackProbeURLs)
	if err != nil {
		return GeoInfo{IP: ip}, err
	}
	geo.IP = firstNonEmpty(geo.IP, ip)
	return geo, nil
}

func lookupProxyOutboundIP(cfg Config, proxyURL *url.URL) (string, error) {
	client := newHTTPClientDuration(effectiveProbeTimeout(cfg), proxyURL)
	var lastErr error
	for _, rawURL := range selectProbeAttempts(cfg.Probes.ProxyIPURLs, cfg.Probes.UseAllProbeURLs, cfg.Probes.FallbackProbeURLs) {
		body, err := httpGetBody(client, rawURL)
		if err != nil {
			lastErr = err
			continue
		}
		ip, err := parseProxyIPResponse(body)
		if err == nil && ip != "" {
			return ip, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("all outbound ip lookups failed")
	}
	return "", lastErr
}

func parseProxyIPResponse(body string) (string, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return "", errors.New("empty outbound ip response")
	}
	if strings.HasPrefix(body, "{") {
		var payload map[string]any
		if err := json.Unmarshal([]byte(body), &payload); err == nil {
			for _, key := range []string{"ip", "query", "origin"} {
				if candidate := strings.TrimSpace(asString(payload[key])); net.ParseIP(candidate) != nil {
					return candidate, nil
				}
			}
		}
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			candidate := strings.TrimSpace(parts[1])
			if net.ParseIP(candidate) != nil {
				return candidate, nil
			}
			continue
		}
		if net.ParseIP(line) != nil {
			return line, nil
		}
	}
	return "", errors.New("no ip in outbound ip response")
}

func lookupLocalGeo(dbPath, ip string) (GeoInfo, error) {
	if strings.TrimSpace(dbPath) == "" {
		return GeoInfo{}, errors.New("local geo db disabled")
	}
	reader, err := openLocalGeoDB(dbPath)
	if err != nil {
		return GeoInfo{}, err
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return GeoInfo{}, errors.New("invalid ip for local geo")
	}
	var record mmdbGeoRecord
	if err := reader.Lookup(parsedIP, &record); err != nil {
		return GeoInfo{}, err
	}
	return geoInfoFromGeoRecord(record, ip)
}

func openLocalGeoDB(path string) (*maxminddb.Reader, error) {
	if localGeoReader != nil && localGeoPath == path {
		return localGeoReader, nil
	}
	if localGeoErr != nil && localGeoPath == path {
		return nil, localGeoErr
	}
	reader, err := maxminddb.Open(path)
	localGeoPath = path
	localGeoReader = reader
	localGeoErr = err
	if err != nil {
		return nil, err
	}
	return reader, nil
}

func lookupLocalGeoCity(dbPath, ip string) (GeoInfo, error) {
	if strings.TrimSpace(dbPath) == "" {
		return GeoInfo{}, errors.New("local city geo db disabled")
	}
	reader, err := openLocalGeoCityDB(dbPath)
	if err != nil {
		return GeoInfo{}, err
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return GeoInfo{}, errors.New("invalid ip for local city geo")
	}
	var record mmdbGeoCityRecord
	if err := reader.Lookup(parsedIP, &record); err != nil {
		return GeoInfo{}, err
	}
	country := firstNonEmpty(record.Country.Names["en"], record.Country.ISOCode)
	code := strings.ToUpper(record.Country.ISOCode)
	state := ""
	if len(record.Subdivisions) > 0 {
		state = firstNonEmpty(record.Subdivisions[0].Names["en"], record.Subdivisions[0].Names["fa"])
	}
	if code == "" {
		return GeoInfo{}, errors.New("local geo had no country match")
	}
	return GeoInfo{
		Country:     country,
		CountryCode: code,
		State:       state,
		Flag:        countryFlag(code),
		IP:          ip,
	}, nil
}

func geoInfoFromGeoRecord(record mmdbGeoRecord, ip string) (GeoInfo, error) {
	country := firstNonEmpty(record.Country.Names["en"], record.Country.ISOCode)
	code := strings.ToUpper(record.Country.ISOCode)
	state := ""
	if len(record.Subdivisions) > 0 {
		state = record.Subdivisions[0].Names["en"]
	}
	if code == "" {
		return GeoInfo{}, errors.New("local city geo had no country match")
	}
	return GeoInfo{
		Country:     country,
		CountryCode: code,
		State:       state,
		Flag:        countryFlag(code),
		IP:          ip,
	}, nil
}

func openLocalGeoCityDB(path string) (*maxminddb.Reader, error) {
	if localGeoCityReader != nil && localGeoCityPath == path {
		return localGeoCityReader, nil
	}
	if localGeoCityErr != nil && localGeoCityPath == path {
		return nil, localGeoCityErr
	}
	reader, err := maxminddb.Open(path)
	localGeoCityPath = path
	localGeoCityReader = reader
	localGeoCityErr = err
	if err != nil {
		return nil, err
	}
	return reader, nil
}

func geoLookup(urls []string, ip string, proxyURL *url.URL, timeoutSeconds int, useAll, allowFallback bool) (GeoInfo, error) {
	client := newHTTPClient(timeoutSeconds, proxyURL)
	var lastErr error
	for _, rawURL := range selectProbeAttempts(urls, useAll, allowFallback) {
		target := strings.ReplaceAll(rawURL, "{ip}", ip)
		body, err := httpGetBody(client, target)
		if err != nil {
			lastErr = err
			continue
		}
		geo, err := parseGeoResponse(body)
		if err == nil && geo.CountryCode != "" {
			return geo, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("all geo lookups failed")
	}
	return GeoInfo{}, lastErr
}

func parseGeoResponse(body string) (GeoInfo, error) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return GeoInfo{}, err
	}
	if strings.EqualFold(asString(payload["status"]), "fail") {
		return GeoInfo{}, errors.New("geo provider returned fail")
	}
	country := firstNonEmpty(asString(payload["country"]), asString(payload["country_name"]))
	code := strings.ToUpper(firstNonEmpty(asString(payload["countryCode"]), asString(payload["country_code"])))
	state := firstNonEmpty(asString(payload["regionName"]), asString(payload["region"]))
	ip := firstNonEmpty(asString(payload["query"]), asString(payload["ip"]))
	if country == "" && code == "" {
		return GeoInfo{}, errors.New("missing country fields")
	}
	if country == "" {
		country = code
	}
	if code == "" {
		code = countryToCode(country)
	}
	return GeoInfo{
		Country:     country,
		CountryCode: code,
		State:       state,
		Flag:        countryFlag(code),
		IP:          ip,
	}, nil
}

func hardReject(rec Record) (bool, string) {
	details := rec.Details
	params := asMap(details["params"])
	auth := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		asString(details["id"]),
		asString(details["auth"]),
		asString(details["password"]),
		asString(details["private_key"]),
	)))
	if auth == "" && requiresAuth(rec.Protocol) {
		return true, "blank authentication"
	}
	if isPrivateHost(rec.Host) {
		return true, "private or loopback host"
	}
	if rec.Port <= 0 || rec.Port > 65535 {
		return true, "invalid port"
	}
	if hasPlaceholderValue(rec.Host) {
		return true, "placeholder host"
	}
	sni := firstNonEmpty(asString(params["sni"]), asString(details["sni"]))
	if hasPlaceholderValue(sni) {
		return true, "placeholder sni"
	}
	payloads := []string{
		rec.Host,
		sni,
		asString(details["path"]),
		asString(params["path"]),
		asString(params["host"]),
		asString(details["host"]),
		asString(params["serviceName"]),
		asString(params["authority"]),
		asString(params["sni"]),
	}
	badTokens := []string{"<script", "<iframe", "<?php", "../", "%2e%2e%2f", "/etc/passwd", " bash ", " wget ", " curl ", ";", "${", "$(", "`", "cmd.exe", "powershell", "sh -c", "javascript:", "vbscript:", "data:text/html", "http-equiv", "window.location", "document.location"}
	for _, payload := range payloads {
		lower := " " + strings.ToLower(payload) + " "
		for _, token := range badTokens {
			if strings.Contains(lower, token) {
				return true, "suspicious injection payload"
			}
		}
	}
	if rec.Protocol == "ss" {
		cipher := strings.ToLower(asString(details["method"]))
		vulnerable := []string{"rc4", "rc4-md5", "bf-cfb", "aes-128-cfb", "aes-256-cfb", "aes-192-cfb", "des-cfb", "cast5-cfb", "idea-cfb", "none"}
		for _, item := range vulnerable {
			if cipher == item || strings.HasPrefix(cipher, item+"-") {
				return true, "obsolete shadowsocks cipher"
			}
		}
	}
	if rec.Protocol == "vless" && strings.EqualFold(asString(params["security"]), "reality") {
		if strings.TrimSpace(asString(params["pbk"])) == "" {
			return true, "reality without public key"
		}
		if hasPlaceholderValue(firstNonEmpty(asString(params["sni"]), asString(params["host"]))) {
			return true, "reality with placeholder sni"
		}
	}
	return false, ""
}

func scoreSecurity(rec Record, activeFindings []ActiveFinding) (int, string, []string) {
	score := 500
	issues := make([]string, 0, 16)
	details := rec.Details
	params := asMap(details["params"])
	auth := strings.TrimSpace(firstNonEmpty(
		asString(details["id"]),
		asString(details["auth"]),
		asString(details["password"]),
		asString(details["private_key"]),
	))

	hasTLS := false
	insecureTLS := false
	network := normalizeTransport(firstNonEmpty(asString(params["type"]), asString(details["net"]), "tcp"))
	securityMode := normalizeStreamSecurity(firstNonEmpty(asString(params["security"]), asString(details["tls"]), "none"))
	switch rec.Protocol {
	case "vmess":
		hasTLS = strings.EqualFold(asString(details["tls"]), "tls")
		if strings.EqualFold(asString(details["scy"]), "none") && !hasTLS {
			issues = append(issues, "no cipher and no tls")
			score -= 150
		}
	case "vless", "trojan", "tuic", "hysteria2", "hysteria", "anytls", "shadowtls", "naive":
		security := strings.ToLower(asString(params["security"]))
		tlsParam := strings.ToLower(asString(params["tls"]))
		hasTLS = security == "tls" || security == "xtls" || security == "reality" || tlsParam == "true" || tlsParam == "1" || rec.Protocol == "tuic" || rec.Protocol == "hysteria2" || rec.Protocol == "hysteria" || rec.Protocol == "anytls" || rec.Protocol == "shadowtls" || rec.Protocol == "naive"
		if !hasTLS {
			issues = append(issues, "missing tls or reality")
			score -= 150
		}
		if strings.EqualFold(asString(params["verify_cert"]), "false") {
			insecureTLS = true
			issues = append(issues, "certificate verification disabled")
			score -= 120
		}
	case "ss":
		method := strings.ToLower(asString(details["method"]))
		if strings.Contains(method, "rc4") || strings.Contains(method, "table") || strings.Contains(method, "md5") || strings.Contains(method, "none") {
			issues = append(issues, "legacy shadowsocks cipher")
			score -= 120
		}
	case "ssr":
		if strings.EqualFold(asString(details["method"]), "none") {
			issues = append(issues, "missing ssr crypto")
			score -= 150
		}
	case "socks", "http":
		issues = append(issues, "legacy proxy protocol")
		score -= 200
		if strings.TrimSpace(asString(details["auth"])) == "" {
			issues = append(issues, "no proxy authentication")
			score -= 100
		}
	}
	if strings.EqualFold(asString(params["allowInsecure"]), "true") || asString(params["allowInsecure"]) == "1" || strings.EqualFold(asString(details["allowInsecure"]), "true") || asString(details["allowInsecure"]) == "1" {
		insecureTLS = true
		issues = append(issues, "allowInsecure enabled")
		score -= 110
	}
	if hasPlaceholderValue(firstNonEmpty(asString(params["sni"]), asString(details["sni"]), rec.Host)) {
		issues = append(issues, "placeholder sni or host")
		score -= 90
	}
	if isNumericIP(rec.Host) && hasTLS {
		issues = append(issues, "tls over ip literal")
		score -= 40
	}
	if network == "kcp" {
		issues = append(issues, "deprecated mkcp transport")
		score -= 100
	}
	if network == "http" && !hasTLS {
		issues = append(issues, "h2/http transport without tls")
		score -= 120
	}
	if network == "ws" {
		if strings.TrimSpace(firstNonEmpty(asString(params["path"]), asString(details["path"]))) == "" {
			issues = append(issues, "websocket without path")
			score -= 40
		}
		if strings.TrimSpace(firstNonEmpty(asString(params["host"]), asString(details["host"]), asString(params["sni"]))) == "" && !isNumericIP(rec.Host) {
			issues = append(issues, "websocket without host or sni")
			score -= 40
		}
	}
	if network == "xhttp" && securityMode != "reality" && securityMode != "tls" && securityMode != "xtls" {
		issues = append(issues, "xhttp without modern transport security")
		score -= 90
	}
	if network == "grpc" && !hasTLS {
		issues = append(issues, "grpc without tls")
		score -= 80
	}
	if network == "grpc" && strings.TrimSpace(firstNonEmpty(asString(params["serviceName"]), asString(details["serviceName"]))) == "" {
		issues = append(issues, "grpc without service name")
		score -= 50
	}
	if network == "quic" && !hasTLS && rec.Protocol != "hysteria" && rec.Protocol != "hysteria2" && rec.Protocol != "tuic" {
		issues = append(issues, "quic without tls")
		score -= 90
	}
	if rec.Protocol == "ssr" {
		obfs := strings.ToLower(asString(details["obfs"]))
		if obfs == "" || obfs == "plain" || obfs == "origin" {
			issues = append(issues, "ssr without safe obfs")
			score -= 60
		}
	}
	if rec.Protocol == "shadowtls" {
		version := intFromAny(params["version"])
		if version > 0 && version < 3 {
			issues = append(issues, "shadowtls legacy version")
			score -= 80
		}
	}
	if rec.Protocol == "ssh" {
		issues = append(issues, "ssh tunnel is easier to fingerprint than tls-based transports")
		score -= 80
	}
	if !hasRemoteDNS(rec) {
		issues = append(issues, "no remote dns declaration")
		score -= 80
	}
	if strings.EqualFold(asString(params["udp"]), "0") || strings.EqualFold(asString(params["udp"]), "false") {
		issues = append(issues, "udp disabled")
		score -= 120
	}
	if strings.EqualFold(asString(params["mux"]), "1") || strings.EqualFold(asString(params["mux"]), "true") {
		issues = append(issues, "mux enabled")
		score -= 80
	}
	if hasTLS && !insecureTLS {
		fingerprint := strings.ToLower(firstNonEmpty(asString(params["fp"]), asString(params["fingerprint"]), asString(params["utls"]), asString(params["uTLS"]), asString(details["fp"])))
		if fingerprint == "" {
			issues = append(issues, "missing tls fingerprint")
			score -= 70
		}
		if !isKnownFingerprint(fingerprint) {
			issues = append(issues, "non-standard fingerprint")
			score -= 40
		}
		alpn := firstNonEmpty(asString(params["alpn"]), asString(details["alpn"]))
		if alpn == "" {
			issues = append(issues, "missing alpn")
			score -= 60
		}
		if sni := firstNonEmpty(asString(params["sni"]), asString(details["sni"])); sni == "" && rec.Protocol != "hysteria" && rec.Protocol != "hysteria2" {
			issues = append(issues, "missing sni")
			score -= 70
		}
		if strings.TrimSpace(asString(params["ech"])) == "" && strings.TrimSpace(asString(params["echConfigList"])) == "" && strings.TrimSpace(asString(params["esni"])) == "" && securityMode == "tls" {
			issues = append(issues, "no ech/esni")
			score -= 10
		}
		if strings.TrimSpace(asString(params["fragment"])) == "" && strings.TrimSpace(asString(params["tlsfragment"])) == "" && network == "tcp" {
			issues = append(issues, "no tls fragmentation")
			score -= 10
		}
		if securityMode == "reality" {
			if strings.TrimSpace(asString(params["pbk"])) == "" {
				issues = append(issues, "reality missing public key")
				score -= 120
			}
			if strings.TrimSpace(asString(params["sid"])) == "" {
				issues = append(issues, "reality missing short id")
				score -= 30
			}
		}
		if strings.TrimSpace(asString(params["flow"])) == "" && strings.EqualFold(rec.Protocol, "vless") && securityMode == "xtls" {
			issues = append(issues, "xtls without vision flow")
			score -= 60
		}
	}
	for _, badPort := range []int{21, 22, 23, 25, 135, 139, 445, 3389} {
		if rec.Port == badPort {
			issues = append(issues, "administrative port")
			score -= 150
			break
		}
	}
	if strings.Contains(strings.ToLower(rec.Host), "duckdns.org") || strings.Contains(strings.ToLower(rec.Host), "ddns.net") || strings.Contains(strings.ToLower(rec.Host), "no-ip") {
		issues = append(issues, "dynamic dns host")
		score -= 50
	}
	if weakCredentialPenalty(rec) > 0 {
		issues = append(issues, "weak credential entropy")
		score -= weakCredentialPenalty(rec)
	}
	if rec.Protocol == "vmess" && !isLikelyUUID(asString(details["id"])) {
		issues = append(issues, "vmess uuid looks invalid")
		score -= 160
	}
	if (rec.Protocol == "vless" || rec.Protocol == "tuic") && auth != "" && !strings.Contains(auth, ":") && !isLikelyUUID(firstSegment(auth, ":")) {
		issues = append(issues, "uuid auth looks invalid")
		score -= 160
	}
	for _, finding := range activeFindings {
		if strings.TrimSpace(finding.Message) == "" {
			continue
		}
		issues = append(issues, "active probe: "+finding.Message)
		score -= finding.Penalty
	}
	if score < 0 {
		score = 0
	}
	if score > 500 {
		score = 500
	}
	level := "risk"
	switch {
	case score >= 400:
		level = "safe"
	case score >= 250:
		level = "low risk"
	case score >= 125:
		level = "medium risk"
	}
	return score, level, issues
}

func hasRemoteDNS(rec Record) bool {
	details := rec.Details
	params := asMap(details["params"])
	for _, key := range []string{"dns", "doh", "dot", "doq", "dnscrypt", "fakeip", "fake-ip", "reverse_mapping", "reverseMapping", "mdns"} {
		if strings.TrimSpace(asString(params[key])) != "" {
			return true
		}
	}
	for _, key := range []string{"dns", "doh", "dot", "doq", "dnscrypt", "fakeip", "fake-ip", "reverse_mapping", "reverseMapping", "mdns"} {
		if strings.TrimSpace(asString(details[key])) != "" {
			return true
		}
	}
	return false
}

func writeOutputs(cfg Config, state *State, logger Logger) error {
	currentOutputs := collectOutputData(cfg, state)
	for _, path := range []string{cfg.Paths.ConfigsDir, cfg.Paths.CountryDir, cfg.Paths.ProtocolDir, cfg.Paths.SecurityDir, cfg.Paths.SpeedDir} {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	if err := ensureRuntimePaths(cfg); err != nil {
		return err
	}
	files := renderOutputFiles(cfg, currentOutputs)
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return err
		}
	}
	logger.console("scheduler", "outputs refreshed pinged=%d security=%d", len(currentOutputs.AllPinged), len(currentOutputs.AllSecurityTested))
	return nil
}

type OutputData struct {
	AllScraped        []string
	AllPinged         []string
	AllSecurityTested []string
	Country           map[string][]string
	Protocol          map[string][]string
	SecuritySpeed     map[string][]string
	SecurityLevel     map[string][]string
}

func collectOutputData(cfg Config, state *State) OutputData {
	data := OutputData{
		Country:       map[string][]string{},
		Protocol:      map[string][]string{},
		SecuritySpeed: map[string][]string{},
		SecurityLevel: map[string][]string{},
	}
	keys := make([]string, 0, len(state.Records))
	for key := range state.Records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		rec := state.Records[key]
		if rec.Rejected {
			continue
		}
		named := rec.NamedRaw
		if named == "" {
			named = formatNamedRaw(*rec)
		}
		data.AllScraped = append(data.AllScraped, named)
		if rec.PingOK {
			data.AllPinged = append(data.AllPinged, named)
			countryFile := filepath.Join(cfg.Paths.CountryDir, sanitizeName(firstNonEmpty(rec.Country, "Unknown"))+".txt")
			protoFile := filepath.Join(cfg.Paths.ProtocolDir, sanitizeName(rec.Protocol)+".txt")
			speedFile := filepath.Join(cfg.Paths.SpeedDir, speedBucket(cfg, rec.SpeedMBps)+".txt")
			data.Country[countryFile] = append(data.Country[countryFile], named)
			data.Protocol[protoFile] = append(data.Protocol[protoFile], named)
			data.SecuritySpeed[speedFile] = append(data.SecuritySpeed[speedFile], named)
		}
		if rec.PingOK && rec.SecurityLevel != "" && rec.SecurityLevel != "unknown" && rec.SecurityLevel != "rejected" {
			if !strings.EqualFold(rec.SecurityLevel, "risk") {
				data.AllSecurityTested = append(data.AllSecurityTested, named)
			}
			secLevelFile := filepath.Join(cfg.Paths.SecurityDir, sanitizeName(rec.SecurityLevel)+".txt")
			data.SecurityLevel[secLevelFile] = append(data.SecurityLevel[secLevelFile], named)
		}
	}
	return data
}

func renderOutputFiles(cfg Config, data OutputData) map[string]string {
	files := map[string]string{
		cfg.Paths.AllScrapedFile:                      joinLines(data.AllScraped),
		activeAllWorkingFile(cfg):                     joinLines(data.AllPinged),
		activeAllSecureFile(cfg):                      joinLines(data.AllSecurityTested),
		filepath.Join(cfg.Paths.CountryDir, ".keep"):  "",
		filepath.Join(cfg.Paths.ProtocolDir, ".keep"): "",
		filepath.Join(cfg.Paths.SecurityDir, ".keep"): "",
		filepath.Join(cfg.Paths.SpeedDir, ".keep"):    "",
	}
	for path, lines := range data.Country {
		files[path] = joinLines(lines)
	}
	for path, lines := range data.Protocol {
		files[path] = joinLines(lines)
	}
	for path, lines := range data.SecuritySpeed {
		files[path] = joinLines(lines)
	}
	for path, lines := range data.SecurityLevel {
		files[path] = joinLines(lines)
	}
	return files
}

func speedBucket(cfg Config, speed float64) string {
	switch {
	case speed >= cfg.Probes.FastSpeedMBps:
		return "fast"
	case speed >= cfg.Probes.MediumSpeedMBps:
		return "medium"
	default:
		return "slow"
	}
}

func formatSpeedKBps(speedMBps float64) string {
	if speedMBps <= 0 {
		return "0KB/s"
	}
	return fmt.Sprintf("%.1fKB/s", speedMBps*1024)
}

func formatNamedRaw(rec Record) string {
	display := formatDisplayName(rec)
	if rec.Protocol == "vmess" {
		details := cloneMap(rec.Details)
		details["ps"] = display
		if _, ok := details["port"]; ok {
			details["port"] = strconv.Itoa(rec.Port)
		}
		raw, _ := json.Marshal(details)
		return "vmess://" + base64.StdEncoding.EncodeToString(raw)
	}
	base := rec.Raw
	if idx := strings.Index(base, "#"); idx >= 0 {
		base = base[:idx]
	}
	return base + "#" + url.QueryEscape(display)
}

func formatDisplayName(rec Record) string {
	country := firstNonEmpty(rec.Country, "Unknown")
	state := strings.TrimSpace(rec.StateName)
	statePart := ""
	if state != "" {
		statePart = " - " + state
	}
	emoji := emojiRiskMap[strings.ToLower(rec.SecurityLevel)]
	if emoji == "" {
		if rec.Rejected {
			emoji = emojiRiskMap["rejected"]
		} else {
			emoji = emojiRiskMap["unknown"]
		}
	}
	speed := "n/a"
	if rec.SpeedMBps > 0 {
		speed = formatSpeedKBps(rec.SpeedMBps)
	}
	score := rec.SecurityScore
	if score < 0 {
		score = 0
	}
	flag := firstNonEmpty(rec.Flag, countryFlag(rec.CountryCode))
	return strings.TrimSpace(fmt.Sprintf("%s %s%s %s %d ⚡%s %s", flag, country, statePart, emoji, score, speed, strings.ToUpper(rec.Protocol)))
}

func activeAllWorkingFile(cfg Config) string {
	return firstNonEmpty(cfg.Paths.AllWorkingFile, cfg.Paths.AllPingedFile, filepath.Join(cfg.Paths.ConfigsDir, "all_working.txt"))
}

func activeAllSecureFile(cfg Config) string {
	return firstNonEmpty(cfg.Paths.AllSecureFile, cfg.Paths.AllSecurityTested, filepath.Join(cfg.Paths.ConfigsDir, "all_secure.txt"))
}

func syncGitHub(cfg Config, state *State, logger Logger) error {
	currentFiles := renderOutputFiles(cfg, collectOutputData(cfg, state))
	client := newHTTPClient(cfg.Probes.TimeoutSeconds, nil)
	logger.console("github", "sync starting files=%d", len(currentFiles))
	currentRemote := make([]string, 0, len(currentFiles))
	paths := make([]string, 0, len(currentFiles))
	for path := range currentFiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, file := range paths {
		remotePath := remotePathForGitHub(cfg, file)
		if err := githubUpsertFile(client, cfg.GitHub, remotePath, currentFiles[file], "update "+remotePath); err != nil {
			return err
		}
		currentRemote = append(currentRemote, remotePath)
		logger.file("github", "synced %s", remotePath)
	}
	for _, oldFile := range state.LastSyncedFiles {
		if !contains(currentRemote, oldFile) {
			if err := githubDeleteFile(client, cfg.GitHub, oldFile, "delete stale "+oldFile); err != nil {
				logger.file("github", "delete failed %s err=%v", oldFile, err)
				continue
			}
		}
	}
	state.LastSyncedFiles = currentRemote
	logger.console("github", "synced %d files", len(currentRemote))
	return nil
}

func remotePathForGitHub(cfg Config, file string) string {
	basePath := strings.Trim(strings.TrimSpace(cfg.GitHub.BasePath), "/")
	remotePath := filepath.ToSlash(file)
	if basePath != "" {
		return filepath.ToSlash(filepath.Join(basePath, remotePath))
	}
	return remotePath
}

func githubUpsertFile(client *http.Client, cfg GitHubConfig, remotePath, content, message string) error {
	sha, _ := githubGetSHA(client, cfg, remotePath)
	payload := map[string]any{
		"message": message,
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
	}
	if sha != "" {
		payload["sha"] = sha
	}
	if cfg.Branch != "" {
		payload["branch"] = cfg.Branch
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPut, githubContentsURL(cfg.Repository, remotePath), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	data, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("github put %s: %s", resp.Status, strings.TrimSpace(string(data)))
}

func githubDeleteFile(client *http.Client, cfg GitHubConfig, remotePath, message string) error {
	sha, err := githubGetSHA(client, cfg, remotePath)
	if err != nil || sha == "" {
		return err
	}
	payload := map[string]any{"message": message, "sha": sha}
	if cfg.Branch != "" {
		payload["branch"] = cfg.Branch
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodDelete, githubContentsURL(cfg.Repository, remotePath), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	data, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("github delete %s: %s", resp.Status, strings.TrimSpace(string(data)))
}

func githubGetSHA(client *http.Client, cfg GitHubConfig, remotePath string) (string, error) {
	url := githubContentsURL(cfg.Repository, remotePath)
	if cfg.Branch != "" {
		url += "?ref=" + urlQueryEscape(cfg.Branch)
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("github get sha %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	return asString(payload["sha"]), nil
}

func githubContentsURL(repo, remotePath string) string {
	escaped := url.PathEscape(filepath.ToSlash(remotePath))
	escaped = strings.ReplaceAll(escaped, "%2F", "/")
	return "https://api.github.com/repos/" + strings.Trim(repo, "/") + "/contents/" + escaped
}

func newHTTPClient(timeoutSeconds int, proxyURL *url.URL) *http.Client {
	return newHTTPClientDuration(time.Duration(timeoutSeconds)*time.Second, proxyURL)
}

func newHTTPClientDuration(timeout time.Duration, proxyURL *url.URL) *http.Client {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ForceAttemptHTTP2:     false,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func httpGetBody(client *http.Client, rawURL string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "proxyharvest-cli/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func fallbackGeoFromRemarks(remarks string) GeoInfo {
	remarks = strings.TrimSpace(remarks)
	if remarks == "" {
		return GeoInfo{}
	}
	runes := []rune(remarks)
	for i := 0; i+1 < len(runes); i++ {
		r1 := runes[i]
		r2 := runes[i+1]
		if r1 >= 127462 && r1 <= 127487 && r2 >= 127462 && r2 <= 127487 {
			cc := string([]rune{rune('A' + (r1 - 127462)), rune('A' + (r2 - 127462))})
			return GeoInfo{Country: cc, CountryCode: cc, Flag: countryFlag(cc)}
		}
	}
	if strings.Contains(strings.ToLower(remarks), "north macedonia") {
		return GeoInfo{Country: "North Macedonia", CountryCode: "MK", Flag: "🇲🇰"}
	}
	return GeoInfo{}
}

func fallbackGeoFromHost(host string) GeoInfo {
	host = strings.ToLower(host)
	keywords := map[string]GeoInfo{
		".mk":       {Country: "North Macedonia", CountryCode: "MK", Flag: "🇲🇰"},
		"macedonia": {Country: "North Macedonia", CountryCode: "MK", Flag: "🇲🇰"},
		"frankfurt": {Country: "Germany", CountryCode: "DE", Flag: "🇩🇪"},
		"germany":   {Country: "Germany", CountryCode: "DE", Flag: "🇩🇪"},
		"singapore": {Country: "Singapore", CountryCode: "SG", Flag: "🇸🇬"},
		"tokyo":     {Country: "Japan", CountryCode: "JP", Flag: "🇯🇵"},
		"tehran":    {Country: "Iran", CountryCode: "IR", Flag: "🇮🇷"},
		"london":    {Country: "United Kingdom", CountryCode: "GB", Flag: "🇬🇧"},
		".us":       {Country: "United States", CountryCode: "US", Flag: "🇺🇸"},
		".de":       {Country: "Germany", CountryCode: "DE", Flag: "🇩🇪"},
		".sg":       {Country: "Singapore", CountryCode: "SG", Flag: "🇸🇬"},
		".ir":       {Country: "Iran", CountryCode: "IR", Flag: "🇮🇷"},
		".jp":       {Country: "Japan", CountryCode: "JP", Flag: "🇯🇵"},
		".gb":       {Country: "United Kingdom", CountryCode: "GB", Flag: "🇬🇧"},
	}
	for token, geo := range keywords {
		if strings.Contains(host, token) {
			return geo
		}
	}
	return GeoInfo{Country: "Unknown", CountryCode: "UN", Flag: "🌐"}
}

func inferGeoHint(cfg Config, host, remarks string) GeoInfo {
	if geo := fallbackGeoFromRemarks(remarks); geo.CountryCode != "" || geo.Country != "" {
		if geo.Country == geo.CountryCode && len(geo.CountryCode) == 2 {
			geo.Country = firstNonEmpty(fallbackGeoFromHost("."+strings.ToLower(geo.CountryCode)).Country, geo.Country)
		}
		if geo.Flag == "" {
			geo.Flag = countryFlag(geo.CountryCode)
		}
		return geo
	}
	if isNumericIP(host) {
		if geo, err := lookupLocalGeo(cfg.Probes.LocalGeoDB, host); err == nil && geo.CountryCode != "" {
			return geo
		}
	}
	return fallbackGeoFromHost(host)
}

func parseQueryMap(query string) map[string]any {
	result := make(map[string]any)
	if query == "" {
		return result
	}
	query = strings.TrimSpace(html.UnescapeString(query))
	query = strings.ReplaceAll(query, "&amp;", "&")
	query = strings.TrimPrefix(query, "?")
	values, err := url.ParseQuery(query)
	if err != nil {
		return result
	}
	for key, items := range values {
		if len(items) > 0 {
			result[normalizeQueryKey(key)] = html.UnescapeString(items[0])
		}
	}
	return result
}

func normalizeQueryKey(key string) string {
	key = strings.TrimSpace(html.UnescapeString(key))
	for strings.HasPrefix(strings.ToLower(key), "amp;") {
		key = key[4:]
	}
	return key
}

func normalizeProtocol(protocol string) string {
	switch strings.ToLower(protocol) {
	case "hy2":
		return "hysteria2"
	case "hy":
		return "hysteria"
	case "wg":
		return "wireguard"
	case "socks4", "socks4a", "socks5":
		return "socks"
	case "blackhole":
		return "block"
	case "freedom":
		return "direct"
	default:
		return strings.ToLower(protocol)
	}
}

func normalizeTransport(transport string) string {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "websocket":
		return "ws"
	case "httpupgrade":
		return "httpupgrade"
	case "grpc":
		return "grpc"
	case "kcp", "mkcp":
		return "kcp"
	case "http/2", "http2", "h2":
		return "http"
	case "quic":
		return "quic"
	case "xhttp", "splithttp":
		return "xhttp"
	case "domainsocket", "unix", "uds", "ds":
		return "uds"
	default:
		return strings.ToLower(strings.TrimSpace(transport))
	}
}

func normalizeStreamSecurity(security string) string {
	switch strings.ToLower(strings.TrimSpace(security)) {
	case "", "none":
		return "none"
	case "tls":
		return "tls"
	case "xtls", "vision", "xtls-rprx-vision":
		return "xtls"
	case "reality":
		return "reality"
	default:
		return strings.ToLower(strings.TrimSpace(security))
	}
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return strings.ToLower(host)
}

func splitHostPort(raw string, defaultPort int) (string, int) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0
	}
	if strings.HasPrefix(raw, "[") && strings.Contains(raw, "]") {
		if host, port, err := net.SplitHostPort(raw); err == nil {
			return normalizeHost(host), mustPort(port, defaultPort)
		}
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		return normalizeHost(host), mustPort(port, defaultPort)
	}
	if idx := strings.LastIndex(raw, ":"); idx >= 0 && idx < len(raw)-1 && !strings.Contains(raw[idx+1:], ":") {
		return normalizeHost(raw[:idx]), mustPort(raw[idx+1:], defaultPort)
	}
	return normalizeHost(raw), defaultPort
}

func splitCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitCSVToAny(raw string) []any {
	parts := splitCSV(raw)
	out := make([]any, 0, len(parts))
	for _, part := range parts {
		out = append(out, part)
	}
	return out
}

func stringSliceFromAny(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := strings.TrimSpace(asString(item)); text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		if text := strings.TrimSpace(asString(value)); text != "" {
			return splitCSV(text)
		}
		return nil
	}
}

func endpointKey(host string, port int) string {
	return fmt.Sprintf("%s:%d", normalizeHost(host), port)
}

func decodeBase64(input string) string {
	clean := strings.NewReplacer("-", "+", "_", "/", "\n", "", "\r", "", " ", "").Replace(strings.TrimSpace(input))
	candidates := []string{clean}
	normalized := clean
	for len(normalized)%4 != 0 {
		normalized += "="
	}
	if normalized != clean {
		candidates = append(candidates, normalized)
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, candidate := range candidates {
		for _, encoding := range encodings {
			data, err := encoding.DecodeString(candidate)
			if err == nil && len(data) > 0 {
				return string(data)
			}
		}
	}
	return input
}

func parsePort(raw string, fallback int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func defaultPortForProtocol(protocol string) int {
	switch protocol {
	case "socks":
		return 1080
	case "http":
		return 80
	case "mixed":
		return 1080
	case "ssh":
		return 22
	case "tor":
		return 9050
	case "ss", "ssr":
		return 8388
	case "wireguard":
		return 51820
	case "dns":
		return 53
	default:
		return 443
	}
}

func requiresAuth(protocol string) bool {
	switch protocol {
	case "vmess", "vless", "trojan", "tuic", "hysteria2", "hysteria", "ss", "ssr", "anytls", "shadowtls", "naive", "ssh":
		return true
	default:
		return false
	}
}

func isPrivateHost(host string) bool {
	host = normalizeHost(host)
	if host == "localhost" || host == "0.0.0.0" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	for _, pattern := range privateIPPatterns {
		if pattern.MatchString(host) {
			return true
		}
	}
	return false
}

func pickIP(ips []net.IP) string {
	for _, ip := range ips {
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	if len(ips) > 0 {
		return ips[0].String()
	}
	return ""
}

func countryFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 {
		if code == "LAN" {
			return "🏠"
		}
		return "🌐"
	}
	runes := []rune(code)
	return string([]rune{127397 + runes[0], 127397 + runes[1]})
}

func countryToCode(country string) string {
	lookup := map[string]string{
		"north macedonia": "MK",
		"germany":         "DE",
		"united states":   "US",
		"singapore":       "SG",
		"japan":           "JP",
		"iran":            "IR",
		"united kingdom":  "GB",
	}
	if code, ok := lookup[strings.ToLower(strings.TrimSpace(country))]; ok {
		return code
	}
	return "UN"
}

func writeJSON(path string, value any) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func parseTime(value string) (time.Time, bool) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339, value)
	return ts, err == nil
}

func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(dedupeStrings(lines), "\n") + "\n"
}

func dedupeStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func shortHash(value string) string {
	return sha1Hex(value)[:12]
}

func sha1Hex(value string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(value)))
}

func sanitizeName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "*", "-", "?", "", `"`, "", "<", "", ">", "", "|", "", "\t", " ")
	value = replacer.Replace(value)
	value = strings.Join(strings.Fields(value), " ")
	return value
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func fallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func ternaryString(condition bool, yes, no string) string {
	if condition {
		return yes
	}
	return no
}

func asString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case int:
		return strconv.Itoa(v)
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func firstNonEmptyAny(values ...any) any {
	for _, value := range values {
		if strings.TrimSpace(asString(value)) != "" {
			return value
		}
	}
	return nil
}

func asMap(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return map[string]any{}
}

func intFromAny(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(v))
		return i
	default:
		return 0
	}
}

func mustPort(raw string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func splitAuthPair(value string) (string, string) {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) == 1 {
		return strings.TrimSpace(parts[0]), ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func firstSegment(value, sep string) string {
	parts := strings.SplitN(value, sep, 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func secondSegment(value, sep string) string {
	parts := strings.SplitN(value, sep, 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func deepCloneMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return cloneMap(input)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return cloneMap(input)
	}
	return out
}

func isLikelyUUID(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return false
	}
	matched, _ := regexp.MatchString(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, value)
	return matched
}

func hasPlaceholderValue(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	placeholders := []string{"example.com", "example.org", "test.com", "your-domain", "your_server", "changeme", "placeholder", "domain.com"}
	for _, item := range placeholders {
		if strings.Contains(value, item) {
			return true
		}
	}
	return false
}

func isNumericIP(value string) bool {
	return net.ParseIP(strings.TrimSpace(value)) != nil
}

func isKnownFingerprint(value string) bool {
	if value == "" {
		return false
	}
	known := map[string]struct{}{
		"chrome": {}, "firefox": {}, "safari": {}, "edge": {}, "ios": {}, "android": {}, "random": {}, "randomized": {}, "randomised": {},
	}
	_, ok := known[strings.ToLower(strings.TrimSpace(value))]
	return ok
}

func weakCredentialPenalty(rec Record) int {
	candidate := strings.TrimSpace(firstNonEmpty(
		asString(rec.Details["password"]),
		asString(rec.Details["auth"]),
		asString(rec.Details["id"]),
	))
	if candidate == "" {
		return 0
	}
	if strings.Contains(candidate, ":") {
		candidate = secondSegment(candidate, ":")
	}
	switch {
	case len(candidate) < 6:
		return 100
	case len(candidate) < 10:
		return 50
	default:
		return 0
	}
}

func findingsToStrings(findings []ActiveFinding) []string {
	if len(findings) == 0 {
		return nil
	}
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		if strings.TrimSpace(finding.Message) != "" {
			out = append(out, finding.Message)
		}
	}
	return out
}

func probeLabel(probe ActiveSecurityProbe) string {
	if strings.TrimSpace(probe.Name) != "" {
		return probe.Name
	}
	return probe.URL
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func probePenalty(probe ActiveSecurityProbe, fallback int) int {
	if probe.Penalty > 0 {
		return probe.Penalty
	}
	switch strings.ToLower(strings.TrimSpace(probe.Severity)) {
	case "critical":
		return maxInt(fallback, 150)
	case "high":
		return maxInt(fallback, 100)
	case "medium":
		return maxInt(fallback, 70)
	case "low":
		return maxInt(fallback, 40)
	default:
		return maxInt(fallback, 40)
	}
}

func inspectJSONProbeBody(body []byte) (int, int, bool) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, 0, false
	}
	status := intFromAny(firstNonEmptyAny(payload["Status"], payload["status"]))
	answers := 0
	if answerSlice, ok := payload["Answer"].([]any); ok {
		answers = len(answerSlice)
	} else if answerSlice, ok := payload["answer"].([]any); ok {
		answers = len(answerSlice)
	}
	return status, answers, true
}

func tlsVersionString(resp *http.Response) string {
	if resp == nil || resp.TLS == nil {
		return ""
	}
	switch resp.TLS.Version {
	case 0x0301:
		return "TLS1.0"
	case 0x0302:
		return "TLS1.1"
	case 0x0303:
		return "TLS1.2"
	case 0x0304:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", resp.TLS.Version)
	}
}

func tlsVersionPenalty(version string) int {
	switch version {
	case "TLS1.0", "TLS1.1":
		return 150
	default:
		return 0
	}
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum[:])
}

func containsFold(items []string, value string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(value)) {
			return true
		}
	}
	return false
}

func uniqueCount(items []string) int {
	seen := map[string]struct{}{}
	for _, item := range items {
		seen[strings.ToLower(strings.TrimSpace(item))] = struct{}{}
	}
	return len(seen)
}

func allSameInt(values []int) bool {
	if len(values) < 2 {
		return true
	}
	first := values[0]
	for _, value := range values[1:] {
		if value != first {
			return false
		}
	}
	return true
}

func urlQueryEscape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func (l Logger) console(section, format string, args ...any) {
	if !l.cfg.Logging.ConsoleVerbose && section != "scheduler" {
		return
	}
	line := fmt.Sprintf(format, args...)
	if l.ui != nil && l.ui.Active() {
		l.ui.Log(section, line)
		return
	}
	fmt.Printf("[%s] %s\n", strings.ToUpper(section), line)
}

func (l Logger) file(section, format string, args ...any) {
	settings, ok := l.cfg.Logging.Sections[section]
	if !ok || !settings.FileEnabled {
		return
	}
	path := filepath.Join(l.cfg.Logging.Directory, sanitizeName(section)+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	line := fmt.Sprintf("%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
	_, _ = f.WriteString(line)
}

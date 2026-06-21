package main

import (
	"encoding/base64"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExtractProxyLinksHandlesConcatenationAndHTML(t *testing.T) {
	input := strings.Join([]string{
		`vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&amp;type=ws&amp;host=edge.example.com&amp;path=%2Fws#one`,
		`vmess://` + mustBase64(`{"v":"2","ps":"two","add":"vmess.example.com","port":"443","id":"22222222-2222-2222-2222-222222222222","aid":"0","net":"grpc","type":"gun","host":"","path":"svc","tls":"tls","sni":"vmess.example.com"}`),
		` trojan://secret@example.net:443?security=tls&ech=cloudflare-ech.com+https://dns.example/dns-query#three`,
	}, "")

	links := extractProxyLinks(input)
	if len(links) != 3 {
		t.Fatalf("expected 3 links, got %d: %#v", len(links), links)
	}
	if !strings.Contains(links[0], "&type=ws") {
		t.Fatalf("expected html entities to be normalized, got %q", links[0])
	}
	if !strings.Contains(links[2], "https://dns.example/dns-query") {
		t.Fatalf("expected embedded https URL in query to survive extraction, got %q", links[2])
	}
}

func TestParseProxyRecognizesRequestedSchemes(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		protocol string
		port     int
	}{
		{"socks4", `socks4://user:pass@example.com:1080`, "socks", 1080},
		{"socks4a", `socks4a://example.com:1080`, "socks", 1080},
		{"socks5", `socks5://example.com:1080`, "socks", 1080},
		{"http", `http://user:pass@example.com:8080`, "http", 8080},
		{"mixed", `mixed://127.0.0.1:2080`, "mixed", 2080},
		{"ss", `ss://` + mustBase64("aes-128-gcm:secret") + `@example.com:8388`, "ss", 8388},
		{"ssr", `ssr://` + mustBase64("example.com:8388:auth_aes128_md5:aes-128-cfb:tls1.2_ticket_auth:"+mustBase64("secret")+"?remarks="+mustBase64("demo")), "ssr", 8388},
		{"vmess", `vmess://` + mustBase64(`{"v":"2","ps":"vmess","add":"vmess.example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"ws","type":"none","host":"edge.example.com","path":"/ws","tls":"tls","sni":"vmess.example.com"}`), "vmess", 443},
		{"vless", `vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws&host=edge.example.com&path=%2Fws`, "vless", 443},
		{"trojan", `trojan://secret@example.com:443?security=tls&type=grpc&serviceName=svc&sni=example.com`, "trojan", 443},
		{"hysteria", `hysteria://secret@example.com:443?sni=example.com&obfs=salamander`, "hysteria", 443},
		{"hysteria2", `hysteria2://secret@example.com:443?sni=example.com&obfs=salamander&obfs-password=pass`, "hysteria2", 443},
		{"tuic", `tuic://11111111-1111-1111-1111-111111111111:secret@example.com:443?sni=example.com`, "tuic", 443},
		{"shadowtls", `shadowtls://secret@example.com:443?version=3&sni=example.com`, "shadowtls", 443},
		{"anytls", `anytls://secret@example.com:443?sni=example.com`, "anytls", 443},
		{"naive", `naive://user:pass@example.com:443?sni=example.com`, "naive", 443},
		{"wireguard", `wireguard://` + placeholderWireGuardKey() + `@example.com:51820?public_key=` + placeholderWireGuardKey() + `&ip=10.0.0.2/32`, "wireguard", 51820},
		{"ssh", `ssh://user:pass@example.com:22`, "ssh", 22},
		{"tor", `tor://example.com:9050`, "tor", 9050},
		{"dns", `dns://resolver.example:53?doh=https://dns.example/dns-query`, "dns", 53},
		{"direct", `direct://gateway.local:443`, "direct", 443},
		{"freedom", `freedom://gateway.local:443`, "direct", 443},
		{"block", `blackhole://drop.local:443`, "block", 443},
		{"selector", `selector://selector.local:443?outbounds=one,two`, "selector", 443},
		{"urltest", `urltest://probe.local:443?outbounds=one,two`, "urltest", 443},
		{"tun", `tun://127.0.0.1:9000`, "tun", 9000},
		{"tproxy", `tproxy://127.0.0.1:12345`, "tproxy", 12345},
		{"redirect", `redirect://127.0.0.1:10080`, "redirect", 10080},
		{"tap", `tap://127.0.0.1:10090`, "tap", 10090},
		{"dokodemo-door", `dokodemo-door://127.0.0.1:5300?target=1.1.1.1&target_port=53`, "dokodemo-door", 5300},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseProxy(tc.raw)
			if err != nil {
				t.Fatalf("parseProxy returned error: %v", err)
			}
			if parsed == nil {
				t.Fatal("parseProxy returned nil")
			}
			if parsed.Protocol != tc.protocol {
				t.Fatalf("expected protocol %q, got %q", tc.protocol, parsed.Protocol)
			}
			if parsed.Port != tc.port {
				t.Fatalf("expected port %d, got %d", tc.port, parsed.Port)
			}
		})
	}
}

func TestXrayRuntimeConfigsValidate(t *testing.T) {
	xrayPath := localCorePath(t, "xray_bin", "xray")
	cases := []string{
		`vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws&host=edge.example.com&path=%2Fws&fp=chrome&alpn=h2,http/1.1&ech=cloudflare-ech.com+https://dns.example/dns-query`,
		`vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=httpupgrade&host=edge.example.com&path=%2Fup&sni=edge.example.com`,
		`vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=grpc&serviceName=svc&sni=edge.example.com&mode=multi`,
		`vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&type=tcp&fp=chrome&pbk=` + placeholderRealityPublicKey() + `&sid=0123456789abcdef&flow=xtls-rprx-vision&sni=www.example.com`,
		`vmess://` + mustBase64(`{"v":"2","ps":"vmess","add":"vmess.example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"grpc","type":"gun","host":"","path":"svc","tls":"tls","sni":"vmess.example.com"}`),
		`trojan://secret@example.com:443?security=tls&type=tcp&headerType=none&sni=example.com`,
		`ss://` + mustBase64("aes-128-gcm:secret") + `@example.com:8388`,
		`socks4a://example.com:1080`,
		`http://user:pass@example.com:8080`,
		`direct://gateway.local:443`,
		`tor://example.com:9050`,
	}

	for _, raw := range cases {
		rec := mustRecordFromRaw(t, raw)
		payload, err := buildXrayConfig(2080, rec)
		if err != nil {
			t.Fatalf("buildXrayConfig failed for %s: %v", rec.Protocol, err)
		}
		if _, err := runCoreValidation(xrayPath, payload, true); err != nil {
			t.Fatalf("xray validation failed for %s: %v", rec.Protocol, err)
		}
	}
}

func TestSingBoxRuntimeConfigsValidate(t *testing.T) {
	singBoxPath := localCorePath(t, "singbox_bin", "sing-box")
	cases := []string{
		`hysteria://secret@example.com:443?sni=example.com&obfs=salamander`,
		`hysteria2://secret@example.com:443?sni=example.com&obfs=salamander&obfs-password=pass`,
		`tuic://11111111-1111-1111-1111-111111111111:secret@example.com:443?sni=example.com`,
		`ssh://user:pass@example.com:22`,
	}

	for _, raw := range cases {
		rec := mustRecordFromRaw(t, raw)
		payload, err := buildSingBoxConfig(2080, rec)
		if err != nil {
			t.Fatalf("buildSingBoxConfig failed for %s: %v", rec.Protocol, err)
		}
		if _, err := runCoreValidation(singBoxPath, payload, false); err != nil {
			t.Fatalf("sing-box validation failed for %s: %v", rec.Protocol, err)
		}
	}
}

func TestExtendedTransportAndSecurityNormalization(t *testing.T) {
	if got := normalizeTransport("xhttp"); got != "xhttp" {
		t.Fatalf("expected xhttp transport normalization, got %q", got)
	}
	if got := normalizeTransport("HTTP/2"); got != "http" {
		t.Fatalf("expected http/2 to normalize to http, got %q", got)
	}
	if got := normalizeTransport("DomainSocket"); got != "uds" {
		t.Fatalf("expected domainsocket to normalize to uds, got %q", got)
	}
	if got := normalizeStreamSecurity("xtls-rprx-vision"); got != "xtls" {
		t.Fatalf("expected vision to normalize to xtls, got %q", got)
	}

	rec := mustRecordFromRaw(t, `vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=xhttp&host=edge.example.com&path=%2Fsplit&mode=packet-up&ech=cloudflare-ech.com+https://dns.example/dns-query&sni=edge.example.com`)
	stream := buildXrayStreamSettings(rec.Protocol, rec.Host, rec.Details, asMap(rec.Details["params"]))
	if stream["network"] != "xhttp" {
		t.Fatalf("expected xhttp network in stream settings, got %#v", stream["network"])
	}
	httpSettings, ok := stream["xhttpSettings"].(map[string]any)
	if !ok {
		t.Fatalf("expected xhttpSettings in stream settings, got %#v", stream)
	}
	if httpSettings["mode"] != "packet-up" {
		t.Fatalf("expected xhttp mode to survive parsing, got %#v", httpSettings["mode"])
	}
}

func TestSecurityAndDNSFeatureParametersRemainSupported(t *testing.T) {
	rec := mustRecordFromRaw(t, `vless://11111111-1111-1111-1111-111111111111@edge.cloudflare.com:443?security=tls&type=tcp&sni=cdn.cloudflare.com&alpn=h2,http/1.1&utls=chrome&ech=config.example&esni=legacy-esni&fragment=1-3&dns=udp://1.1.1.1&dot=tls://dns.google&doh=https://dns.google/dns-query&doq=quic://dns.adguard-dns.com&dnscrypt=sdns://AQcAAAAAAAAAEzE3Ni4xMDMuMTMwLjEzMDo0NDM&fakeip=1&reverse_mapping=1&mdns=1`)
	params := asMap(rec.Details["params"])

	for _, key := range []string{"dns", "dot", "doh", "doq", "dnscrypt", "fakeip", "reverse_mapping", "mdns", "utls", "ech", "esni", "fragment"} {
		if strings.TrimSpace(asString(params[key])) == "" {
			t.Fatalf("expected parameter %q to be preserved, params=%#v", key, params)
		}
	}
	if !hasRemoteDNS(rec) {
		t.Fatal("expected remote DNS feature set to be recognized")
	}

	_, _, issues := scoreSecurity(rec, nil)
	for _, forbidden := range []string{"no remote dns declaration", "missing tls fingerprint", "no ech/esni", "no tls fragmentation"} {
		if containsString(issues, forbidden) {
			t.Fatalf("did not expect issue %q in %#v", forbidden, issues)
		}
	}
}

func TestStructuralValidationConfigsValidate(t *testing.T) {
	xrayPath := localCorePath(t, "xray_bin", "xray")
	singBoxPath := localCorePath(t, "singbox_bin", "sing-box")
	cases := []struct {
		raw     string
		useXray bool
	}{
		{`block://drop.local:443`, false},
		{`selector://selector.local:443?outbounds=one,two`, false},
		{`urltest://probe.local:443?outbounds=one,two`, false},
		{`mixed://127.0.0.1:2080`, false},
		{`tproxy://127.0.0.1:12345`, false},
		{`redirect://127.0.0.1:10080`, false},
		{`shadowtls://secret@example.com:443?version=3&sni=example.com`, false},
		{`dns://resolver.example:53?doh=https://dns.example/dns-query`, true},
		{`dokodemo-door://127.0.0.1:5300?target=1.1.1.1&target_port=53`, true},
	}

	for _, tc := range cases {
		rec := mustRecordFromRaw(t, tc.raw)
		var (
			payload map[string]any
			err     error
			path    string
		)
		if tc.useXray {
			path = xrayPath
			payload, err = buildXrayValidationConfig(rec)
		} else {
			path = singBoxPath
			payload, err = buildSingBoxValidationConfig(rec)
		}
		if err != nil {
			t.Fatalf("validation builder failed for %s: %v", rec.Protocol, err)
		}
		if _, err := runCoreValidation(path, payload, tc.useXray); err != nil {
			t.Fatalf("core validation failed for %s: %v", rec.Protocol, err)
		}
	}
}

func TestSelectProtocolTestPlanHandlesBundledCoreGaps(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		mode testMode
	}{
		{
			name: "xray-uds",
			raw:  `vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=uds&path=C:/tmp/proxy.sock&sni=edge.example.com`,
			mode: testModeSyntheticValidation,
		},
		{
			name: "xray-h2",
			raw:  `vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=h2&host=edge.example.com&path=%2Fh2&sni=edge.example.com`,
			mode: testModeSyntheticValidation,
		},
		{
			name: "xray-mkcp",
			raw:  `vless://11111111-1111-1111-1111-111111111111@example.com:443?security=none&type=mkcp&seed=demo&headerType=none`,
			mode: testModeSyntheticValidation,
		},
		{
			name: "xray-quic",
			raw:  `vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=quic&quicSecurity=none&key=demo&headerType=srtp&sni=edge.example.com`,
			mode: testModeSyntheticValidation,
		},
		{
			name: "naive",
			raw:  `naive://user:pass@example.com:443?sni=example.com`,
			mode: testModeSyntheticValidation,
		},
		{
			name: "tun",
			raw:  `tun://127.0.0.1:9000`,
			mode: testModeSyntheticValidation,
		},
		{
			name: "wireguard",
			raw:  `wireguard://` + placeholderWireGuardKey() + `@example.com:51820?public_key=` + placeholderWireGuardKey() + `&ip=10.0.0.2/32`,
			mode: testModeSyntheticValidation,
		},
		{
			name: "tap",
			raw:  `tap://127.0.0.1:10090`,
			mode: testModeSyntheticValidation,
		},
		{
			name: "shadowtls",
			raw:  `shadowtls://secret@example.com:443?version=3&sni=example.com`,
			mode: testModeCoreValidation,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := mustRecordFromRaw(t, tc.raw)
			plan := selectProtocolTestPlan(rec)
			if plan.mode != tc.mode {
				t.Fatalf("expected mode %v, got %v", tc.mode, plan.mode)
			}
		})
	}
}

func TestRunParallelTCPPrechecksBatchesApplicableRecords(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	cfg := defaultConfig()
	cfg.Probes.EnableTCPPrecheck = true
	cfg.Probes.TCPPrecheckTimeoutMS = 150
	logger := Logger{cfg: cfg}

	openRec := Record{
		EndpointKey: "open",
		Protocol:    "direct",
		Host:        "127.0.0.1",
		Port:        listener.Addr().(*net.TCPAddr).Port,
		Details:     map[string]any{},
	}
	closedRec := Record{
		EndpointKey: "closed",
		Protocol:    "direct",
		Host:        "127.0.0.1",
		Port:        listener.Addr().(*net.TCPAddr).Port + 1,
		Details:     map[string]any{},
	}
	skippedRec := Record{
		EndpointKey: "hysteria",
		Protocol:    "hysteria",
		Host:        "127.0.0.1",
		Port:        listener.Addr().(*net.TCPAddr).Port,
		Details:     map[string]any{"params": map[string]any{}},
	}

	results := runParallelTCPPrechecks(cfg, []*Record{&openRec, &closedRec, &skippedRec}, logger)
	if len(results) != 2 {
		t.Fatalf("expected only applicable records to be prechecked, got %d results", len(results))
	}
	if !results["open"].Attempted || !results["open"].OK || results["open"].Err != nil {
		t.Fatalf("expected open endpoint to pass precheck, got %#v", results["open"])
	}
	if !results["closed"].Attempted || results["closed"].OK || results["closed"].Err == nil {
		t.Fatalf("expected closed endpoint to fail precheck, got %#v", results["closed"])
	}
	if _, ok := results["hysteria"]; ok {
		t.Fatalf("did not expect hysteria record to be prechecked")
	}
}

func TestDecodeMenuKeyEventsSplitsBufferedRuntimeKeys(t *testing.T) {
	events := decodeMenuKeyEvents([]byte{'p', 'r', 'q'})
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d: %#v", len(events), events)
	}
	if events[0] != "p" || events[1] != "r" || events[2] != "quit" {
		t.Fatalf("unexpected decoded events: %#v", events)
	}

	arrow := decodeMenuKeyEvents([]byte{0x1b, '[', 'A', ' ', 'c'})
	if len(arrow) != 3 {
		t.Fatalf("expected 3 events for arrow sequence, got %d: %#v", len(arrow), arrow)
	}
	if arrow[0] != "up" || arrow[1] != " " || arrow[2] != "c" {
		t.Fatalf("unexpected mixed decoded events: %#v", arrow)
	}
}

func TestJSONSyntheticValidationReasonHandlesBundledCoreGaps(t *testing.T) {
	cases := []struct {
		name     string
		payload  string
		expected string
	}{
		{
			name:     "sing-box-naive",
			payload:  `{"outbounds":[{"type":"naive","server":"example.com","server_port":443,"username":"user","password":"pass"}]}`,
			expected: "naive outbound",
		},
		{
			name:     "sing-box-tap",
			payload:  `{"inbounds":[{"type":"tap","interface_name":"sb"}],"outbounds":[{"type":"direct"}]}`,
			expected: "tap inbound",
		},
		{
			name:     "xray-uds",
			payload:  `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111"}]}]},"streamSettings":{"network":"uds","dsSettings":{"path":"C:/tmp/proxy.sock"}}}]}`,
			expected: "uds/domain-socket transport",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := mustRecordFromRaw(t, `json://`+mustBase64(tc.payload))
			reason := jsonSyntheticValidationReason(rec.Details, asMap(rec.Details["json_config"]))
			if !strings.Contains(reason, tc.expected) {
				t.Fatalf("expected reason to contain %q, got %q", tc.expected, reason)
			}
		})
	}
}

func mustRecordFromRaw(t *testing.T, raw string) Record {
	t.Helper()
	parsed, err := parseProxy(raw)
	if err != nil {
		t.Fatalf("parseProxy(%q) failed: %v", raw, err)
	}
	return Record{
		Protocol: parsed.Protocol,
		Raw:      parsed.Raw,
		Host:     parsed.Host,
		Port:     parsed.Port,
		Remarks:  parsed.Remarks,
		Details:  parsed.Details,
	}
}

func localCorePath(t *testing.T, dir, base string) string {
	t.Helper()
	name := base
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(dir, name)
	if !fileExists(path) {
		t.Skipf("core binary missing: %s", path)
	}
	return path
}

func mustBase64(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

func placeholderRealityPublicKey() string {
	return base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

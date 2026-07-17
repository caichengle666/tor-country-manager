package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const onionooDetailsURL = "https://onionoo.torproject.org/details?running=true&type=relay&flag=Exit&fields=fingerprint,nickname,or_addresses,exit_addresses,country,country_name,as,as_name,consensus_weight,exit_policy_summary"

type ExitNode struct {
	Fingerprint     string    `json:"fingerprint"`
	Nickname        string    `json:"nickname"`
	IP              string    `json:"ip"`
	ORAddress       string    `json:"or_address,omitempty"`
	CountryCode     string    `json:"country_code"`
	CountryName     string    `json:"country_name"`
	Continent       string    `json:"continent"`
	ASN             string    `json:"asn,omitempty"`
	ISP             string    `json:"isp,omitempty"`
	ConsensusWeight int64     `json:"consensus_weight,omitempty"`
	LatencyMS       int       `json:"latency_ms"`
	LatencyChecked  time.Time `json:"-"`
}

type ExitCountry struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	Continent string `json:"continent"`
	NodeCount int    `json:"node_count"`
}

type ExitCatalog struct {
	cfg        Config
	client     *http.Client
	mu         sync.RWMutex
	refreshMu  sync.Mutex
	nodes      map[string]ExitNode
	fetchedAt  time.Time
	lastError  string
	latencySem chan struct{}
}

type CatalogStatus struct {
	LastUpdated time.Time `json:"last_updated,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	NodeCount   int       `json:"node_count"`
	Stale       bool      `json:"stale"`
}

func NewExitCatalog(cfg Config) *ExitCatalog {
	return &ExitCatalog{
		cfg:        cfg,
		client:     catalogClient(cfg),
		nodes:      make(map[string]ExitNode),
		latencySem: make(chan struct{}, 10),
	}
}

func catalogClient(cfg Config) *http.Client {
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if cfg.UpstreamSOCKS5 != "" {
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialViaUpstreamSOCKS5(ctx, cfg.UpstreamSOCKS5, address, cfg.UpstreamUsername, cfg.UpstreamPassword)
		}
	}
	return &http.Client{Timeout: 35 * time.Second, Transport: transport}
}

func (c *ExitCatalog) UpdateUpstream(cfg Config) {
	c.mu.Lock()
	c.cfg.UpstreamSOCKS5 = cfg.UpstreamSOCKS5
	c.cfg.UpstreamUsername = cfg.UpstreamUsername
	c.cfg.UpstreamPassword = cfg.UpstreamPassword
	c.client = catalogClient(c.cfg)
	c.fetchedAt = time.Time{}
	c.mu.Unlock()
}

func (c *ExitCatalog) EnsureFresh(ctx context.Context) error {
	err := c.refresh(ctx, false)
	if err != nil && c.Status().NodeCount > 0 {
		return nil
	}
	return err
}

func (c *ExitCatalog) Refresh(ctx context.Context) error {
	return c.refresh(ctx, true)
}

func (c *ExitCatalog) refresh(ctx context.Context, force bool) error {
	c.mu.RLock()
	fresh := !force && len(c.nodes) > 0 && time.Since(c.fetchedAt) < 10*time.Minute
	c.mu.RUnlock()
	if fresh {
		return nil
	}
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.mu.RLock()
	fresh = !force && len(c.nodes) > 0 && time.Since(c.fetchedAt) < 10*time.Minute
	c.mu.RUnlock()
	if fresh {
		return nil
	}

	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, onionooDetailsURL, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		c.setError(err)
		return fmt.Errorf("load Tor exit directory: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("Tor exit directory returned HTTP %d", response.StatusCode)
		c.setError(err)
		return err
	}
	var document struct {
		Relays []struct {
			Fingerprint     string   `json:"fingerprint"`
			Nickname        string   `json:"nickname"`
			ORAddresses     []string `json:"or_addresses"`
			ExitAddresses   []string `json:"exit_addresses"`
			Country         string   `json:"country"`
			CountryName     string   `json:"country_name"`
			ASN             string   `json:"as"`
			ASName          string   `json:"as_name"`
			ConsensusWeight int64    `json:"consensus_weight"`
			ExitPolicy      struct {
				Accept []string `json:"accept"`
				Reject []string `json:"reject"`
			} `json:"exit_policy_summary"`
		} `json:"relays"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<20)).Decode(&document); err != nil {
		c.setError(err)
		return fmt.Errorf("parse Tor exit directory: %w", err)
	}

	c.mu.Lock()
	updated := make(map[string]ExitNode, len(document.Relays))
	for _, relay := range document.Relays {
		code := normalizeCode(relay.Country)
		ip := chooseExitIP(relay.ExitAddresses, relay.ORAddresses)
		if code == "" || ip == "" || !countryCodePattern.MatchString(code) || !allowsPort(relay.ExitPolicy.Accept, relay.ExitPolicy.Reject, 443) {
			continue
		}
		node := ExitNode{
			Fingerprint:     strings.ToUpper(relay.Fingerprint),
			Nickname:        relay.Nickname,
			IP:              ip,
			ORAddress:       chooseORAddress(relay.ORAddresses),
			CountryCode:     code,
			CountryName:     countryDisplayName(code, relay.CountryName),
			Continent:       continentFor(code),
			ASN:             relay.ASN,
			ISP:             relay.ASName,
			ConsensusWeight: relay.ConsensusWeight,
			LatencyMS:       -1,
		}
		if previous, ok := c.nodes[node.Fingerprint]; ok && time.Since(previous.LatencyChecked) < 5*time.Minute {
			node.LatencyMS = previous.LatencyMS
			node.LatencyChecked = previous.LatencyChecked
		}
		updated[node.Fingerprint] = node
	}
	c.nodes = updated
	c.fetchedAt = time.Now()
	c.lastError = ""
	c.mu.Unlock()
	return nil
}

func (c *ExitCatalog) Status() CatalogStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return CatalogStatus{
		LastUpdated: c.fetchedAt,
		LastError:   c.lastError,
		NodeCount:   len(c.nodes),
		Stale:       c.fetchedAt.IsZero() || time.Since(c.fetchedAt) >= 10*time.Minute || c.lastError != "",
	}
}

func allowsPort(accept, reject []string, port int) bool {
	if len(accept) > 0 {
		return rangesContainPort(accept, port)
	}
	if len(reject) > 0 {
		return !rangesContainPort(reject, port)
	}
	return false
}

func rangesContainPort(ranges []string, port int) bool {
	for _, value := range ranges {
		parts := strings.SplitN(value, "-", 2)
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		end := start
		if len(parts) == 2 {
			end, err = strconv.Atoi(parts[1])
			if err != nil {
				continue
			}
		}
		if port >= start && port <= end {
			return true
		}
	}
	return false
}

func (c *ExitCatalog) setError(err error) {
	c.mu.Lock()
	c.lastError = err.Error()
	c.mu.Unlock()
}

func chooseExitIP(exitAddresses, orAddresses []string) string {
	for _, address := range exitAddresses {
		if ip := net.ParseIP(strings.Trim(address, "[]")); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	for _, address := range orAddresses {
		host, _, err := net.SplitHostPort(address)
		if err == nil {
			if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
				return ip.String()
			}
		}
	}
	return ""
}

func chooseORAddress(addresses []string) string {
	for _, address := range addresses {
		host, port, err := net.SplitHostPort(address)
		if err == nil {
			if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
				return net.JoinHostPort(host, port)
			}
		}
	}
	return ""
}

func (c *ExitCatalog) Countries() []ExitCountry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	byCode := make(map[string]ExitCountry)
	for _, node := range c.nodes {
		country := byCode[node.CountryCode]
		country.Code = node.CountryCode
		country.Name = countryDisplayName(node.CountryCode, node.CountryName)
		country.Continent = node.Continent
		country.NodeCount++
		byCode[node.CountryCode] = country
	}
	countries := make([]ExitCountry, 0, len(byCode))
	for _, country := range byCode {
		countries = append(countries, country)
	}
	sort.Slice(countries, func(i, j int) bool {
		left, right := continentOrder(countries[i].Continent), continentOrder(countries[j].Continent)
		if left != right {
			return left < right
		}
		return countries[i].Name < countries[j].Name
	})
	return countries
}

func (c *ExitCatalog) NodesForCountry(code string) []ExitNode {
	code = normalizeCode(code)
	c.mu.RLock()
	nodes := make([]ExitNode, 0)
	for _, node := range c.nodes {
		if node.CountryCode == code {
			nodes = append(nodes, node)
		}
	}
	c.mu.RUnlock()
	sort.Slice(nodes, func(i, j int) bool { return lessExitNode(nodes[i], nodes[j]) })
	return nodes
}

func latencyRank(latency int) int {
	if latency >= 0 {
		return 0
	}
	if latency == -1 {
		return 1
	}
	return 2
}

func lessExitNode(left, right ExitNode) bool {
	leftRank, rightRank := latencyRank(left.LatencyMS), latencyRank(right.LatencyMS)
	if leftRank != rightRank {
		return leftRank < rightRank
	}
	if left.LatencyMS >= 0 && left.LatencyMS != right.LatencyMS {
		return left.LatencyMS < right.LatencyMS
	}
	return left.ConsensusWeight > right.ConsensusWeight
}

func (c *ExitCatalog) Node(fingerprint string) (ExitNode, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	node, ok := c.nodes[strings.ToUpper(fingerprint)]
	return node, ok
}

func (c *ExitCatalog) SelectNode(ctx context.Context, countries []string, policy string) (ExitNode, error) {
	if len(countries) == 0 {
		return ExitNode{}, errors.New("at least one country is required")
	}
	seen := make(map[string]bool)
	normalized := make([]string, 0, len(countries))
	for _, country := range countries {
		code := normalizeCode(country)
		if !countryCodePattern.MatchString(code) {
			return ExitNode{}, fmt.Errorf("invalid country code %q", country)
		}
		if !seen[code] {
			seen[code] = true
			normalized = append(normalized, code)
		}
	}
	if len(normalized) > 20 {
		return ExitNode{}, errors.New("no more than 20 candidate countries are allowed")
	}
	if policy == "" {
		policy = "lowest_latency"
	}
	if policy != "lowest_latency" && policy != "failover" {
		return ExitNode{}, errors.New("policy must be lowest_latency or failover")
	}
	for _, code := range normalized {
		c.startLatencyChecks(code, 10)
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ExitNode{}, ctx.Err()
	case <-timer.C:
	}
	if node, ok := c.bestCandidate(normalized, policy, true); ok {
		return node, nil
	}
	if node, ok := c.bestCandidate(normalized, policy, false); ok {
		return node, nil
	}
	return ExitNode{}, errors.New("none of the requested countries currently has a usable Tor exit node")
}

func (c *ExitCatalog) bestCandidate(countries []string, policy string, requireMeasured bool) (ExitNode, bool) {
	var candidates []ExitNode
	for _, code := range countries {
		nodes := c.NodesForCountry(code)
		if policy == "failover" && len(nodes) > 0 {
			for _, node := range nodes {
				if !requireMeasured || node.LatencyMS >= 0 {
					return node, true
				}
			}
			if !requireMeasured {
				return nodes[0], true
			}
		}
		for _, node := range nodes {
			if !requireMeasured || node.LatencyMS >= 0 {
				candidates = append(candidates, node)
			}
		}
	}
	if len(candidates) == 0 {
		return ExitNode{}, false
	}
	sort.Slice(candidates, func(i, j int) bool { return lessExitNode(candidates[i], candidates[j]) })
	return candidates[0], true
}

func (c *ExitCatalog) StartLatencyChecks(code string) {
	c.startLatencyChecks(code, 0)
}

func (c *ExitCatalog) startLatencyChecks(code string, limit int) {
	nodes := c.NodesForCountry(code)
	if limit > 0 && len(nodes) > limit {
		nodes = nodes[:limit]
	}
	for _, node := range nodes {
		if !node.LatencyChecked.IsZero() && time.Since(node.LatencyChecked) < 5*time.Minute {
			continue
		}
		fingerprint := node.Fingerprint
		go func() {
			c.latencySem <- struct{}{}
			defer func() { <-c.latencySem }()
			latency := c.measureTCPLatency(node.ORAddress)
			c.mu.Lock()
			current, ok := c.nodes[fingerprint]
			if ok {
				current.LatencyMS = latency
				current.LatencyChecked = time.Now()
				c.nodes[fingerprint] = current
			}
			c.mu.Unlock()
		}()
	}
}

func (c *ExitCatalog) measureTCPLatency(address string) int {
	if address == "" {
		return -2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	var connection net.Conn
	var err error
	c.mu.RLock()
	cfg := c.cfg
	c.mu.RUnlock()
	if cfg.UpstreamSOCKS5 != "" {
		connection, err = dialViaUpstreamSOCKS5(ctx, cfg.UpstreamSOCKS5, address, cfg.UpstreamUsername, cfg.UpstreamPassword)
	} else {
		dialer := net.Dialer{Timeout: 4 * time.Second}
		connection, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return -2
	}
	_ = connection.Close()
	elapsed := time.Since(started).Milliseconds()
	if elapsed < 1 {
		return 1
	}
	return int(elapsed)
}

var continentByCode = buildContinentMap()

func buildContinentMap() map[string]string {
	continents := map[string]string{}
	add := func(name, codes string) {
		for _, code := range strings.Fields(codes) {
			continents[strings.ToLower(code)] = name
		}
	}
	add("亚洲", "AF AM AZ BH BD BT BN KH CN CY GE HK IN ID IR IQ IL JP JO KZ KW KG LA LB MO MY MV MN MM NP KP KR OM PK PS PH QA SA SG LK SY TW TJ TH TL TR TM AE UZ VN YE")
	add("欧洲", "AL AD AT BY BE BA BG HR CZ DK EE FI FR DE GR HU IS IE IT LV LI LT LU MT MD MC ME NL MK NO PL PT RO RU SM RS SK SI ES SE CH UA GB VA XK")
	add("北美洲", "AG BS BB BZ BM CA CR CU DM DO SV GL GD GT HT HN JM MX NI PA PM KN LC VC TT US")
	add("南美洲", "AR BO BR CL CO EC FK GF GY PY PE SR UY VE")
	add("非洲", "DZ AO BJ BW BF BI CV CM CF TD KM CG CD CI DJ EG GQ ER SZ ET GA GM GH GN GW KE LS LR LY MG MW ML MR MU YT MA MZ NA NE NG RE RW SH ST SN SC SL SO ZA SS SD TZ TG TN UG EH ZM ZW")
	add("大洋洲", "AS AU CK FJ PF GU KI MH FM NR NC NZ NU MP PW PG WS SB TK TO TV VU WF")
	add("南极洲", "AQ BV TF HM GS")
	return continents
}

func continentFor(code string) string {
	if continent, ok := continentByCode[normalizeCode(code)]; ok {
		return continent
	}
	return "其他"
}

func continentOrder(name string) int {
	order := map[string]int{"亚洲": 0, "欧洲": 1, "北美洲": 2, "南美洲": 3, "非洲": 4, "大洋洲": 5, "南极洲": 6, "其他": 7}
	if value, ok := order[name]; ok {
		return value
	}
	return 99
}

var chineseCountryNames = map[string]string{
	"us": "美国", "ca": "加拿大", "mx": "墨西哥", "cr": "哥斯达黎加", "pa": "巴拿马", "gt": "危地马拉", "hn": "洪都拉斯", "sv": "萨尔瓦多", "do": "多米尼加",
	"br": "巴西", "ar": "阿根廷", "cl": "智利", "co": "哥伦比亚", "pe": "秘鲁", "uy": "乌拉圭", "py": "巴拉圭", "ec": "厄瓜多尔", "ve": "委内瑞拉",
	"gb": "英国", "de": "德国", "fr": "法国", "nl": "荷兰", "se": "瑞典", "no": "挪威", "fi": "芬兰", "dk": "丹麦", "is": "冰岛", "ie": "爱尔兰", "be": "比利时", "lu": "卢森堡", "ch": "瑞士", "at": "奥地利", "es": "西班牙", "pt": "葡萄牙", "it": "意大利", "pl": "波兰", "cz": "捷克", "sk": "斯洛伐克", "hu": "匈牙利", "ro": "罗马尼亚", "bg": "保加利亚", "gr": "希腊", "hr": "克罗地亚", "si": "斯洛文尼亚", "rs": "塞尔维亚", "ba": "波黑", "me": "黑山", "mk": "北马其顿", "al": "阿尔巴尼亚", "ee": "爱沙尼亚", "lv": "拉脱维亚", "lt": "立陶宛", "ua": "乌克兰", "md": "摩尔多瓦", "by": "白俄罗斯", "ru": "俄罗斯",
	"cn": "中国", "jp": "日本", "sg": "新加坡", "in": "印度", "id": "印度尼西亚", "my": "马来西亚", "th": "泰国", "ph": "菲律宾", "kr": "韩国", "hk": "中国香港", "tw": "中国台湾", "vn": "越南", "il": "以色列", "tr": "土耳其", "cy": "塞浦路斯", "ae": "阿联酋", "kz": "哈萨克斯坦", "ge": "格鲁吉亚", "am": "亚美尼亚", "az": "阿塞拜疆",
	"au": "澳大利亚", "nz": "新西兰",
	"za": "南非", "ma": "摩洛哥", "tn": "突尼斯", "eg": "埃及", "ng": "尼日利亚", "ke": "肯尼亚", "gh": "加纳", "sc": "塞舌尔",
}

func countryDisplayName(code, fallback string) string {
	if name, ok := chineseCountryNames[normalizeCode(code)]; ok {
		return name
	}
	if fallback != "" {
		return fallback
	}
	return strings.ToUpper(code)
}

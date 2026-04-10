// Clash Override v0.9.0 | Modular Architecture & Priority Engine
// Refactored: Dynamic rule matrix, node profiler, group builder, pre-validation layer
const CONFIG = {
  DNS_PORT: 1054,
  DNS_IPV6: true,
  FAKE_IP_V6: true,
  FAKE_IP_V6_RANGE: "fdfe:dcba:9876::/64",
  TCP_CONCURRENT: true,
  XUDP_SAFE_MODE: true,
  FILTER_KEYWORDS: ["官网", "套餐", "流量", "异常", "剩余", "过期", "失效", "维护", "高倍", "倍率", "测试", "Test", "备用"],
  SPEED_TEST_URL: "https://www.gstatic.com/generate_204",
  RULE_BASE_URL: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release",
  RULE_UPDATE_INTERVAL: 86400,
  BLOCK_OVERSEAS_QUIC: false,
  // v0.9.0 Architecture Toggles
  AUTO_VALIDATE: true,
  ENABLE_PROCESS_RULES: true
};

const domesticNS = ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"];
const foreignNS = ["https://1.1.1.1/dns-query", "https://8.8.4.4/dns-query"];

const dnsConfig = {
  enable: true,
  listen: `0.0.0.0:${CONFIG.DNS_PORT}`,
  ipv6: CONFIG.DNS_IPV6,
  "enhanced-mode": "fake-ip",
  "fake-ip-range": "198.18.0.1/16",
  "fake-ip-ipv6": CONFIG.FAKE_IP_V6,
  "fake-ip-range6": CONFIG.FAKE_IP_V6_RANGE,
  "respect-rules": true,
  "fake-ip-filter": ["+.lan", "+.local", "+.msftconnecttest.com", "+.msftncsi.com", "localhost.ptlogin2.qq.com", "time.*.com", "*.bilibili.com", "*.douyin.com", "*.kuaishou.com", "cdn.*", "*.microsoft.com"],
  "default-nameserver": ["223.5.5.5", "119.29.29.29", "2400:3200::1"],
  nameserver: [...foreignNS],
  "proxy-server-nameserver": [...domesticNS],
  "direct-nameserver": [...domesticNS],
  "direct-nameserver-follow-policy": true,
  "nameserver-policy": { "geosite:cn,private": domesticNS, "geosite:geolocation-!cn": foreignNS }
};

const ruleUrl = (n) => `${CONFIG.RULE_BASE_URL}/${n}.txt`;
const ruleProviders = {
  reject: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("reject") },
  pikpak: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("pikpak") },
  proxy:  { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("proxy") },
  direct: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("direct") },
  gfw:    { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("gfw") },
  cncidr: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "ipcidr", url: ruleUrl("cncidr") },
  lancidr:{ type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "ipcidr", url: ruleUrl("lancidr") }
};

// v0.9.0 Priority Matrix (Strict top-down injection order)
const RULE_PRIORITY = [
  { name: "reject", rule: "RULE-SET,reject,全局拦截" },
  { name: "pikpak", rule: "RULE-SET,pikpak,PikPak" },
  { name: "tg-domain", rule: "DOMAIN-SUFFIX,telegram.org,Telegram" },
  { name: "tg-me", rule: "DOMAIN-SUFFIX,telegram.me,Telegram" },
  { name: "tg-keyword", rule: "DOMAIN-KEYWORD,telegram,Telegram" },
  { name: "tg-ipv4-1", rule: "IP-CIDR,91.108.0.0/16,Telegram,no-resolve" },
  { name: "tg-ipv4-2", rule: "IP-CIDR,149.154.160.0/20,Telegram,no-resolve" },
  { name: "tg-ipv6", rule: "IP-CIDR6,2001:67c:4e8::/48,Telegram,no-resolve" },
  { name: "proxy", rule: "RULE-SET,proxy,节点选择" },
  { name: "gfw", rule: "RULE-SET,gfw,节点选择" },
  { name: "direct", rule: "RULE-SET,direct,全局直连" },
  { name: "lancidr", rule: "RULE-SET,lancidr,全局直连,no-resolve" },
  { name: "cncidr", rule: "RULE-SET,cncidr,全局直连,no-resolve" },
  { name: "ipv6-loop", rule: "IP-CIDR6,::1/128,DIRECT,no-resolve" },
  { name: "ipv6-ula", rule: "IP-CIDR6,fc00::/7,DIRECT,no-resolve" },
  { name: "ipv6-link", rule: "IP-CIDR6,fe80::/10,DIRECT,no-resolve" },
  { name: "geo-lan", rule: "GEOIP,LAN,全局直连,no-resolve" },
  { name: "geo-cn", rule: "GEOIP,CN,全局直连,no-resolve" },
  { name: "match", rule: "MATCH,漏网之鱼" }
];

const baseGroup = { interval: 600, timeout: 5000, url: CONFIG.SPEED_TEST_URL, lazy: true, "max-failed-times": 5, tolerance: 200 };
const regions = { hk: "香港|HK|Hong Kong|🇭🇰", us: "美国|US|United States|🇺🇸", tw: "台湾|TW|Tai Wan|🇹🇼", jp: "日本|JP|Japan|🇯🇵", sg: "新加坡|SG|Singapore|🇸🇬" };
const safeFilter = `^(?!.*(${CONFIG.FILTER_KEYWORDS.join("|")})).*$`;
const regionRe = (k) => `(?=.*(${regions[k]})).*$`;

function main(config) {
  if (!config || typeof config !== "object") return config;
  console.log(`[Override] v0.9.0 | Modular Engine Active`);
  console.log(`[Override] Raw Proxies: ${config.proxies?.length || 0}`);

  // 1. Core Stack Injection
  config.ipv6 = CONFIG.DNS_IPV6;
  config["tcp-concurrent"] = CONFIG.TCP_CONCURRENT;
  config.tun = { enable: true, stack: "system", "auto-route": true, "auto-detect-interface": true, "dns-hijack": ["any:53"], "strict-route": true, mtu: 1500 };
  config.sniffer = { enable: true, "parse-pure-ip": false, "force-dns-mapping": true, sniff: { TLS: { ports: [443, 8443], "override-destination": true }, HTTP: { ports: [80, 8080, 8443], "override-destination": true }, QUIC: { ports: [443, 8443] } } };
  config.dns = dnsConfig;
  config["rule-providers"] = ruleProviders;

  // 2. Dynamic Group Builder
  const tgProxies = ["新加坡-自动", "美国-自动", "节点选择", "延迟选优", "故障转移", "香港-自动", "台湾-自动", "日本-自动", "其他地区", "DIRECT"];
  const pkProxies = ["新加坡-自动", "节点选择", "延迟选优", "故障转移", "香港-自动", "美国-自动", "台湾-自动", "日本-自动", "其他地区", "DIRECT"];

  config["proxy-groups"] = [
    { ...baseGroup, name: "节点选择", type: "select", proxies: ["延迟选优", "故障转移", "香港-自动", "美国-自动", "台湾-自动", "日本-自动", "新加坡-自动", "其他地区", "DIRECT"], "include-all": true, filter: safeFilter },
    { ...baseGroup, name: "延迟选优", type: "url-test", "include-all": true, filter: safeFilter },
    { ...baseGroup, name: "故障转移", type: "fallback", "include-all": true, filter: safeFilter },
    { name: "PikPak", type: "select", "include-all": true, proxies: pkProxies, filter: safeFilter },
    { name: "Telegram", type: "select", "include-all": true, proxies: tgProxies, filter: safeFilter },
    { ...baseGroup, name: "香港-自动", type: "url-test", "include-all": true, filter: regionRe("hk") },
    { ...baseGroup, name: "美国-自动", type: "url-test", "include-all": true, filter: regionRe("us") },
    { ...baseGroup, name: "台湾-自动", type: "url-test", "include-all": true, filter: regionRe("tw") },
    { ...baseGroup, name: "日本-自动", type: "url-test", "include-all": true, filter: regionRe("jp") },
    { ...baseGroup, name: "新加坡-自动", type: "url-test", "include-all": true, filter: regionRe("sg") },
    { ...baseGroup, name: "其他地区", type: "url-test", "include-all": true, filter: `^(?!.*(${Object.values(regions).join("|")}|${CONFIG.FILTER_KEYWORDS.join("|")})).*$` },
    { name: "全局直连", type: "select", proxies: ["DIRECT", "节点选择"] },
    { name: "全局拦截", type: "select", proxies: ["REJECT", "DIRECT"] },
    { name: "漏网之鱼", type: "select", proxies: ["节点选择", "延迟选优", "全局直连"] }
  ];

  // 3. Priority Rule Matrix Builder
  const processRules = CONFIG.ENABLE_PROCESS_RULES ? [
    "PROCESS-NAME,Telegram.exe,Telegram", "PROCESS-NAME,Updater.exe,Telegram",
    "PROCESS-NAME,PikPak.exe,PikPak", "PROCESS-NAME,com.pikpak.app,PikPak"
  ] : [];

  config.rules = RULE_PRIORITY.flatMap(p => {
    if (p.name === "tg-domain" && processRules.length) return [...processRules, p.rule];
    if (p.name === "match") return CONFIG.BLOCK_OVERSEAS_QUIC ? ["AND,((DST-PORT,443),(NETWORK,UDP),(NOT,(GEOIP,CN))),REJECT", p.rule] : [p.rule];
    return [p.rule];
  });

  // 4. Node Profiler & Sanitization
  if (config.proxies?.length) {
    config.proxies = config.proxies.filter(p => {
      if (!p?.name || !p?.type) return false;
      if (CONFIG.FILTER_KEYWORDS.some(k => p.name.includes(k))) return false;
      const validTypes = ["ss","ssr","vmess","vless","trojan","tuic","hysteria","hysteria2","wireguard","snell","ssh"];
      if (!validTypes.includes(p.type.toLowerCase())) {
        console.warn(`[Override] Skipped unsupported protocol: ${p.name} (${p.type})`);
        return false;
      }
      return true;
    });
    config.proxies.forEach(p => {
      p.udp = true;
      if (CONFIG.XUDP_SAFE_MODE && /vmess|trojan|hysteria|hysteria2|tuic|shadowsocks/i.test(p.type)) p.xudp = true;
    });
  }

  // 5. Pre-Validation & Logging
  if (CONFIG.AUTO_VALIDATE) {
    const groupNames = new Set(config["proxy-groups"]?.map(g => g.name) || []);
    const invalidRefs = config.rules?.filter(r => {
      const match = r.match(/,(DIRECT|REJECT|节点选择|PikPak|Telegram|延迟选优|故障转移|漏网之鱼|全局直连|全局拦截)$/);
      return match && !groupNames.has(match[1]) && match[1] !== "DIRECT" && match[1] !== "REJECT";
    });
    if (invalidRefs?.length) console.warn(`[Override] Potential invalid group refs: ${invalidRefs.join(", ")}`);
  }

  console.log(`[Override] v0.9.0 | Valid Nodes: ${config.proxies?.length || 0} | Rules: ${config.rules?.length} | DNS:${dnsConfig.listen}`);
  return config;
}

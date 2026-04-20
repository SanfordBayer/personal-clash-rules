// Clash.Meta / Mihomo Regional Extension Script v0.9.29
// Filename: regional-extension.js
// Features: Numerical UI Lock, PikPak Prioritized (Index 04), Removed TG Group
// Optimized for: Clash Verge Rev, FlClash, Mihomo Kernel

const CONFIG = {
  PRESET: "balanced",
  DEBUG: false,
  ENABLE_SMART_SORT: true,
  DNS_PORT: 1053,
  DNS_IPV6: true,
  FAKE_IP_V6: true,
  FAKE_IP_V6_RANGE: "fdfe:dcba:9876::/64",
  TCP_CONCURRENT: true,
  XUDP_SAFE_MODE: true,
  FILTER_KEYWORDS: ["官网","套餐","流量","异常","剩余","过期","失效","维护","高倍","倍率","测试","Test","备用","到期"],
  EXCLUDE_KEYWORDS: ["倍率","测试","0\\.1x","内测","内网","loopback"],
  REGION_WEIGHTS: { sg: 40, hk: 30, jp: 25, us: 20, tw: 20 },
  PROTOCOL_WEIGHTS: { hysteria2: 40, hysteria: 35, tuic: 30, trojan: 25, vmess: 20, vless: 20, ss: 10 },
  SPEED_TEST_URL: "https://www.gstatic.com/generate_204",
  RULE_BASE_URL: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release",
  RULE_UPDATE_INTERVAL: 86400,
  BLOCK_QUIC: "overseas",
  ENABLE_PROCESS_RULES: true,
  ENABLE_WEBRTC_BLOCK: false,
  ENABLE_REGIONAL_GROUPS: true,

  // UI 排序映射表：PikPak 提前至 04，地区组顺延
  UI_MAP: {
    Proxy: "01 | Proxy",
    AutoTest: "02 | AutoTest",
    FailOver: "03 | FailOver",
    PikPak: "04 | PikPak",   // 提前至地区组之前
    HK: "05 | HK",
    SG: "06 | SG",
    JP: "07 | JP",
    US: "08 | US",
    TW: "09 | TW",
    Other: "10 | Other",
    Direct: "11 | Direct",
    Reject: "12 | Reject",
    CatchAll: "13 | CatchAll",
    GLOBAL: "14 | GLOBAL"
  }
};

const getName = (k) => CONFIG.UI_MAP[k] || k;
const filterRegex = new RegExp(CONFIG.FILTER_KEYWORDS.join("|"), "i");
const excludeRegex = new RegExp(CONFIG.EXCLUDE_KEYWORDS.join("|"), "i");
const regionRegex = {
  sg: /新加坡|SG|Singapore|🇸🇬/i,
  hk: /香港|HK|Hong Kong|🇭🇰/i,
  jp: /日本|JP|Japan|🇯🇵/i,
  us: /美国|US|United States|🇺🇸/i,
  tw: /台湾|TW|Tai Wan|🇹/i
};

function scoreNode(name, type) {
  let s = 0;
  for (let k in regionRegex) { if (regionRegex[k].test(name)) { s += CONFIG.REGION_WEIGHTS[k] || 0; break; } }
  const t = (type || "").toLowerCase();
  if (/hysteria2|hy2/.test(t)) s += 40;
  else if (/hysteria/.test(t)) s += 35;
  else if (/tuic/.test(t)) s += 30;
  else if (/trojan/.test(t)) s += 25;
  else if (/vmess|vless|ss|shadowsocks/.test(t)) s += 15;
  return s;
}

function main(config) {
  if (!config || typeof config !== "object") return config;

  config.ipv6 = CONFIG.DNS_IPV6;
  config["tcp-concurrent"] = CONFIG.TCP_CONCURRENT;
  config.tun = { enable: true, stack: "system", "auto-route": true, "auto-detect-interface": true, "dns-hijack": ["0.0.0.0:53"], "strict-route": true };
  config.sniffer = { enable: true, "parse-pure-ip": true, sniff: { TLS: { ports: [443, 8443], "override-destination": true }, HTTP: { ports: [80, 8080], "override-destination": true }, QUIC: { ports: [443] } } };

  // DNS
  const domesticNS = ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"];
  const foreignNS = ["https://1.1.1.1/dns-query", "https://8.8.4.4/dns-query"];
  config.dns = {
    enable: true, listen: `0.0.0.0:${CONFIG.DNS_PORT}`, ipv6: true, "enhanced-mode": "fake-ip",
    "respect-rules": true, "proxy-server-nameserver": [...domesticNS, "223.5.5.5"],
    "nameserver-policy": { "geosite:cn,private": domesticNS, "geosite:geolocation-!cn": foreignNS },
    "default-nameserver": ["223.5.5.5", "119.29.29.29"], nameserver: ["https://dns.alidns.com/dns-query"],
    fallback: foreignNS, "fallback-filter": { geoip: true, "geoip-code": "CN" }
  };

  // Rule Providers
  const ruleUrl = n => `${CONFIG.RULE_BASE_URL}/${n}.txt`;
  config["rule-providers"] = {
    reject: { type: "http", format: "yaml", interval: 86400, behavior: "domain", url: ruleUrl("reject") },
    pikpak: { type: "http", format: "yaml", interval: 86400, behavior: "domain", url: ruleUrl("pikpak") },
    proxy: { type: "http", format: "yaml", interval: 86400, behavior: "domain", url: ruleUrl("proxy") },
    direct: { type: "http", format: "yaml", interval: 86400, behavior: "domain", url: ruleUrl("direct") },
    gfw: { type: "http", format: "yaml", interval: 86400, behavior: "domain", url: ruleUrl("gfw") },
    cncidr: { type: "http", format: "yaml", interval: 86400, behavior: "ipcidr", url: ruleUrl("cncidr") },
    lancidr: { type: "http", format: "yaml", interval: 86400, behavior: "ipcidr", url: ruleUrl("lancidr") }
  };

  if (!config.proxies) return config;
  config.proxies = config.proxies.filter(p => p.name && p.type && !filterRegex.test(p.name) && !excludeRegex.test(p.name));
  
  if (CONFIG.ENABLE_SMART_SORT) {
    const PRIO = { hk: 1, sg: 2, us: 3, jp: 4, tw: 5 };
    const getP = n => { for (let k in PRIO) { if (regionRegex[k].test(n)) return PRIO[k]; } return 99; };
    config.proxies.sort((a, b) => (getP(a.name) - getP(b.name)) || (scoreNode(b.name, b.type) - scoreNode(a.name, a.type)));
  }
  const sortedNames = config.proxies.map(p => p.name);
  config.proxies.forEach(p => { p.udp = true; if (CONFIG.XUDP_SAFE_MODE && /vmess|trojan|hysteria|tuic/i.test(p.type)) p.xudp = true; });

  const base = { interval: 300, timeout: 5000, url: CONFIG.SPEED_TEST_URL, lazy: true, tolerance: 200 };
  const groups = [];
  const regionalKeys = ["HK", "SG", "JP", "US", "TW", "Other"];
  const regionalNames = regionalKeys.map(getName);

  // 1-3. 核心选路组
  groups.push({ name: getName("Proxy"), type: "select", proxies: [getName("AutoTest"), getName("FailOver"), ...regionalNames, ...sortedNames, "DIRECT"] });
  groups.push({ ...base, name: getName("AutoTest"), type: "url-test", "include-all": true, filter: `^(?!.*(${CONFIG.FILTER_KEYWORDS.join("|")})).*$` });
  groups.push({ ...base, name: getName("FailOver"), type: "fallback", "include-all": true, filter: `^(?!.*(${CONFIG.FILTER_KEYWORDS.join("|")})).*$` });

  // 4. PikPak (全节点，SG/Proxy 置顶)
  const pikpakBackends = [getName("SG"), getName("Proxy"), ...sortedNames, "DIRECT"];
  groups.push({ name: getName("PikPak"), type: "select", proxies: pikpakBackends });

  // 5-10. 地区组
  if (CONFIG.ENABLE_REGIONAL_GROUPS) {
    const rStr = { hk: "香港|HK|Hong Kong|🇭", us: "美国|US|United States|🇺🇸", tw: "台湾|TW|Tai Wan|🇹", jp: "日本|JP|Japan|🇯🇵", sg: "新加坡|SG|Singapore|🇸🇬" };
    ["hk", "sg", "jp", "us", "tw"].forEach(k => {
      groups.push({ ...base, name: getName(k.toUpperCase()), type: "url-test", "include-all": true, filter: `(?=.*(${rStr[k]})).*$` });
    });
    groups.push({ ...base, name: getName("Other"), type: "url-test", "include-all": true, filter: `^(?!.*(${Object.values(rStr).join("|")}|${CONFIG.FILTER_KEYWORDS.join("|")})).*$` });
  }

  // 11-14. 功能组
  groups.push({ name: getName("Direct"), type: "select", proxies: ["DIRECT"] }, { name: getName("Reject"), type: "select", proxies: ["REJECT", "DIRECT"] });
  groups.push({ name: getName("CatchAll"), type: "select", proxies: [getName("Proxy"), getName("AutoTest"), "DIRECT"] }, { name: getName("GLOBAL"), type: "select", proxies: ["DIRECT", getName("Proxy")] });

  config["proxy-groups"] = groups;

  let r = [];
  if (CONFIG.ENABLE_WEBRTC_BLOCK) r.push("DOMAIN-KEYWORD,stun,REJECT", "AND,((NETWORK,UDP),(DST-PORT,19302)),REJECT");
  if (CONFIG.BLOCK_QUIC === "overseas") r.push("AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,!CN)),REJECT");
  if (CONFIG.ENABLE_PROCESS_RULES) {
    r.push(`PROCESS-NAME,Telegram.exe,${getName("Proxy")}`, `PROCESS-NAME,PikPak.exe,${getName("PikPak")}`);
  }

  r.push(
    `RULE-SET,reject,${getName("Reject")}`, `RULE-SET,pikpak,${getName("PikPak")}`,
    `DOMAIN-KEYWORD,telegram,${getName("Proxy")}`, `IP-CIDR,91.108.0.0/16,${getName("Proxy")},no-resolve`,
    `RULE-SET,proxy,${getName("Proxy")}`, `RULE-SET,gfw,${getName("Proxy")}`, `RULE-SET,direct,${getName("Direct")}`,
    `GEOIP,LAN,${getName("Direct")},no-resolve`, `GEOIP,CN,${getName("Direct")},no-resolve`, `MATCH,${getName("CatchAll")}`
  );
  config.rules = r;

  return config;
}

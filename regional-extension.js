// Clash.Meta / Mihomo Regional Extension Script v0.9.20
// Filename: regional-extension.js
// Features: WebRTC, DNS Anti-Leak, Regional Groups, Process Routing, QUIC Control, Smart Filter, Fallback
// Compatible: subconverter (&script=), Mihomo >= v1.18.0, Clash.Meta, FlClash

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

  BLOCK_QUIC: "overseas", // global / overseas / off
  ENABLE_PROCESS_RULES: true,
  ENABLE_WEBRTC_BLOCK: false,
  ENABLE_REGIONAL_GROUPS: true
};

// Precompiled Regex
const filterRegex = new RegExp(CONFIG.FILTER_KEYWORDS.join("|"), "i");
const excludeRegex = new RegExp(CONFIG.EXCLUDE_KEYWORDS.join("|"), "i");
const regionRegex = {
  sg: /新加坡|SG|Singapore|🇸🇬/i,
  hk: /香港|HK|Hong Kong|🇭🇰/i,
  jp: /日本|JP|Japan|🇯🇵/i,
  us: /美国|US|United States|🇺🇸/i,
  tw: /台湾|TW|Tai Wan|🇹🇼/i
};

const domesticNS = ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"];
const foreignNS = ["https://1.1.1.1/dns-query", "https://8.8.4.4/dns-query"];

function scoreNode(name, type) {
  let score = 0;
  for (let k in regionRegex) {
    if (regionRegex[k].test(name)) { score += CONFIG.REGION_WEIGHTS[k] || 0; break; }
  }
  const t = (type || "").toLowerCase();
  if (/hysteria2|hy2/.test(t)) score += CONFIG.PROTOCOL_WEIGHTS.hysteria2;
  else if (/hysteria/.test(t)) score += CONFIG.PROTOCOL_WEIGHTS.hysteria;
  else if (/tuic/.test(t)) score += CONFIG.PROTOCOL_WEIGHTS.tuic;
  else if (/trojan/.test(t)) score += CONFIG.PROTOCOL_WEIGHTS.trojan;
  else if (/vmess/.test(t)) score += CONFIG.PROTOCOL_WEIGHTS.vmess;
  else if (/vless/.test(t)) score += CONFIG.PROTOCOL_WEIGHTS.vless;
  else if (/ss|shadowsocks/.test(t)) score += CONFIG.PROTOCOL_WEIGHTS.ss;
  return score;
}

function main(config) {
  if (!config || typeof config !== "object") return config;
  console.log(`[Regional-Extension] v0.9.20 start | preset:${CONFIG.PRESET}`);

  // 1. Core Stack Injection
  config.ipv6 = CONFIG.DNS_IPV6;
  config["tcp-concurrent"] = CONFIG.TCP_CONCURRENT;
  config.tun = { enable: true, stack: "system", "auto-route": true, "auto-detect-interface": true, "dns-hijack": ["0.0.0.0:53", "tcp://0.0.0.0:53"], "strict-route": true, mtu: 1500 };
  config.sniffer = { enable: true, "parse-pure-ip": true, "force-dns-mapping": true, sniff: { TLS: { ports: [443, 8443], "override-destination": true }, HTTP: { ports: [80, 8080, 8443], "override-destination": true }, QUIC: { ports: [443, 8443] } } };

  // 2. DNS Pipeline
  config.dns = {
    enable: true, listen: `0.0.0.0:${CONFIG.DNS_PORT}`, ipv6: true, "filter-aaaa": true,
    "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
    "fake-ip-ipv6": CONFIG.FAKE_IP_V6, "fake-ip-range6": CONFIG.FAKE_IP_V6_RANGE,
    "respect-rules": true,
    "fake-ip-filter": ["*.lan", "*.local", "+.msftconnecttest.com", "+.msftncsi.com", "localhost.ptlogin2.qq.com", "time.*.com", "stun.*.*", "+.srv.nintendo.net", "+.stun.playstation.net", "+.xboxlive.com", "geosite:cn"],
    "default-nameserver": ["223.5.5.5", "119.29.29.29", "2400:3200::1"],
    nameserver: ["https://dns.alidns.com/dns-query"],
    "proxy-server-nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query", "223.5.5.5", "119.29.29.29"],
    fallback: [...foreignNS],
    "fallback-filter": { geoip: true, "geoip-code": "CN" },
    "nameserver-policy": { "geosite:cn,private": domesticNS, "geosite:geolocation-!cn": foreignNS }
  };

  // 3. Rule Providers
  const ruleUrl = n => `${CONFIG.RULE_BASE_URL}/${n}.txt`;
  config["rule-providers"] = {
    reject: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("reject") },
    pikpak: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("pikpak") },
    proxy: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("proxy") },
    direct: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("direct") },
    gfw: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("gfw") },
    cncidr: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "ipcidr", url: ruleUrl("cncidr") },
    lancidr: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "ipcidr", url: ruleUrl("lancidr") }
  };

  // 4. Node Processing & Filtering
  if (!Array.isArray(config.proxies) || config.proxies.length === 0) {
    console.warn("[Regional-Extension] proxies invalid/empty. Injecting safe fallback config.");
    config["proxy-groups"] = [{ name: "节点选择", type: "select", proxies: ["DIRECT"] }];
    config.rules = ["MATCH,DIRECT"];
    config.proxies = [];
    return config;
  }

  const regionStats = { sg: 0, hk: 0, jp: 0, us: 0, tw: 0 };
  config.proxies = config.proxies.filter(p => {
    if (!p?.name || !p?.type) return false;
    if (filterRegex.test(p.name) || excludeRegex.test(p.name)) return false;
    for (let k in regionRegex) { if (regionRegex[k].test(p.name)) { regionStats[k]++; break; } }
    return true;
  });

  if (config.proxies.length === 0) {
    console.warn("[Regional-Extension] All nodes filtered out. Injecting safe fallback config.");
    config["proxy-groups"] = [{ name: "节点选择", type: "select", proxies: ["DIRECT"] }];
    config.rules = ["MATCH,DIRECT"];
    return config;
  }

  // 5. Custom Priority Sort: HK -> SG -> US -> JP -> TW -> Others
  if (CONFIG.ENABLE_SMART_SORT) {
    const REGION_PRIORITY = { hk: 1, sg: 2, us: 3, jp: 4, tw: 5 };
    function getRegionPriority(name) {
      for (let key in REGION_PRIORITY) {
        if (regionRegex[key].test(name)) return REGION_PRIORITY[key];
      }
      return 99;
    }

    config.proxies.sort((a, b) => {
      const prioA = getRegionPriority(a.name);
      const prioB = getRegionPriority(b.name);
      if (prioA !== prioB) return prioA - prioB;
      return scoreNode(b.name, b.type) - scoreNode(a.name, a.type);
    });
  }

  // Extract explicit sorted names to bypass include-all UI sorting
  const sortedProxyNames = config.proxies.map(p => p.name);

  config.proxies.forEach(p => {
    p.udp = true;
    if (CONFIG.XUDP_SAFE_MODE && /vmess|trojan|hysteria|hysteria2|tuic/i.test(p.type)) p.xudp = true;
  });

  // 6. Dynamic Groups Builder
  const baseGroup = { interval: 300, timeout: 5000, url: CONFIG.SPEED_TEST_URL, lazy: true, "max-failed-times": 5, tolerance: 200 };
  const safeFilter = `^(?!.*(${CONFIG.FILTER_KEYWORDS.join("|")})).*$`;
  const regionStr = { hk: "香港|HK|Hong Kong|🇭🇰", us: "美国|US|United States|🇺🇸", tw: "台湾|TW|Tai Wan|🇹🇼", jp: "日本|JP|Japan|🇯🇵", sg: "新加坡|SG|Singapore|🇸🇬" };
  const regionRe = k => `(?=.*(${regionStr[k]})).*$`;
  const otherFilter = `^(?!.*(${Object.values(regionStr).join("|")}|${CONFIG.FILTER_KEYWORDS.join("|")})).*$`;

  const groups = [];
  const regionalLabels = CONFIG.ENABLE_REGIONAL_GROUPS ? ["新加坡-自动", "香港-自动", "日本-自动", "美国-自动", "台湾-自动", "其他地区"] : [];

  groups.push({ ...baseGroup, name: "延迟选优", type: "url-test", "include-all": true, filter: safeFilter });
  groups.push({ ...baseGroup, name: "故障转移", type: "fallback", "include-all": true, filter: safeFilter });

  const appProxies = CONFIG.ENABLE_REGIONAL_GROUPS ? [...regionalLabels, "节点选择", "DIRECT"] : ["节点选择", "DIRECT"];
  if (CONFIG.ENABLE_PROCESS_RULES) {
    groups.push({ name: "Telegram", type: "select", "include-all": true, proxies: appProxies, filter: safeFilter });
    groups.push({ name: "PikPak", type: "select", "include-all": true, proxies: appProxies, filter: safeFilter });
  }

  if (CONFIG.ENABLE_REGIONAL_GROUPS) {
    const regionOrder = ["hk", "us", "tw", "jp", "sg"];
    regionOrder.forEach(k => {
      const label = `${regionStr[k].split("|")[0]}-自动`;
      groups.push({ ...baseGroup, name: label, type: "url-test", "include-all": true, filter: regionRe(k) });
    });
    groups.push({ ...baseGroup, name: "其他地区", type: "url-test", "include-all": true, filter: otherFilter });
  }

  // CRITICAL FIX: Use explicit sorted list instead of include-all to force FlClash/Mihomo UI order
  const mainProxies = CONFIG.ENABLE_REGIONAL_GROUPS 
    ? [...sortedProxyNames, "延迟选优", "故障转移", ...regionalLabels, "DIRECT"] 
    : [...sortedProxyNames, "延迟选优", "故障转移", "DIRECT"];

  groups.unshift({
    name: "节点选择",
    type: "select",
    proxies: mainProxies
    // include-all & filter removed to strictly enforce array order in GUI clients
  });

  groups.push({ name: "全局直连", type: "select", proxies: ["DIRECT", "节点选择"] });
  groups.push({ name: "全局拦截", type: "select", proxies: ["REJECT", "DIRECT"] });
  groups.push({ name: "漏网之鱼", type: "select", proxies: ["节点选择", "延迟选优", "全局直连"] });
  groups.push({ name: "GLOBAL", type: "select", proxies: ["DIRECT", "节点选择", "延迟选优"] });

  config["proxy-groups"] = groups;

  // 7. Dynamic Rules Builder
  let rules = [];

  if (CONFIG.ENABLE_WEBRTC_BLOCK) {
    rules.push("DOMAIN-KEYWORD,stun,REJECT", "DOMAIN-KEYWORD,turn,REJECT", "AND,((NETWORK,UDP),(DST-PORT,19302)),REJECT");
  }

  if (CONFIG.BLOCK_QUIC === "global") {
    rules.push("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT");
  } else if (CONFIG.BLOCK_QUIC === "overseas") {
    rules.push("AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,!CN)),REJECT");
  }

  if (CONFIG.ENABLE_PROCESS_RULES) {
    rules.push("PROCESS-NAME,Telegram.exe,Telegram", "PROCESS-NAME,Updater.exe,Telegram", "PROCESS-NAME,PikPak.exe,PikPak", "PROCESS-NAME,com.pikpak.app,PikPak");
  }

  rules.push(
    "RULE-SET,reject,全局拦截", "RULE-SET,pikpak,PikPak",
    "DOMAIN-SUFFIX,telegram.org,Telegram", "DOMAIN-SUFFIX,telegram.me,Telegram", "DOMAIN-KEYWORD,telegram,Telegram",
    "IP-CIDR,91.108.0.0/16,Telegram,no-resolve", "IP-CIDR,149.154.160.0/20,Telegram,no-resolve", "IP-CIDR6,2001:67c:4e8::/48,Telegram,no-resolve",
    "RULE-SET,proxy,节点选择", "RULE-SET,gfw,节点选择",
    "RULE-SET,direct,全局直连", "RULE-SET,lancidr,全局直连,no-resolve", "RULE-SET,cncidr,全局直连,no-resolve",
    "GEOIP,LAN,全局直连,no-resolve", "GEOIP,CN,全局直连,no-resolve",
    "MATCH,漏网之鱼"
  );

  config.rules = rules;

  // 8. Debug Report
  console.log(`[Regional-Extension] v0.9.20 | Nodes:${config.proxies.length} | Rules:${rules.length} | Groups:${groups.length}`);
  if (CONFIG.DEBUG) {
    console.log(`[Debug] Flags: TG=${CONFIG.ENABLE_PROCESS_RULES} | QUIC=${CONFIG.BLOCK_QUIC} | WebRTC=${CONFIG.ENABLE_WEBRTC_BLOCK} | RG=${CONFIG.ENABLE_REGIONAL_GROUPS}`);
    console.log(`[Debug] Regions:`, JSON.stringify(regionStats));
    console.log(`[Debug] Top 3:`, config.proxies.slice(0, 3).map(p => p.name).join(", "));
  }

  return config;
}

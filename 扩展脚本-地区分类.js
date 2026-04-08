// Clash Override v0.7.1 | Mihomo >= 1.18.0 | Dual-Stack Smart Routing
const CONFIG = {
  DNS_PORT: 1054,
  DNS_IPV6: true,
  FAKE_IP_V6: true,
  TCP_CONCURRENT: true,
  XUDP_SAFE_MODE: true,
  NODE_FILTER_KEYWORDS: ["官网", "套餐", "流量", "异常", "剩余", "过期", "失效", "维护"],
  SPEED_TEST_URL: "https://www.google.com/generate_204",
  RULE_UPDATE_INTERVAL: 86400
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
  "respect-rules": true,
  "fake-ip-filter": ["+.lan", "+.local", "+.msftconnecttest.com", "+.msftncsi.com", "localhost.ptlogin2.qq.com", "time.*.com"],
  "default-nameserver": ["223.5.5.5", "119.29.29.29", "2400:3200::1"],
  nameserver: [...foreignNS],
  "proxy-server-nameserver": [...domesticNS],
  "nameserver-policy": { "geosite:cn,private": domesticNS, "geosite:geolocation-!cn": foreignNS }
};

// Fixed: Return single string for strict type validation in clients like Mihomo Party
const ruleUrl = (n) => `https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/${n}.txt`;
const ruleProviders = {
  reject: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("reject") },
  pikpak: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("pikpak") },
  proxy:  { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("proxy") },
  direct: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("direct") },
  gfw:    { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("gfw") },
  cncidr: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "ipcidr", url: ruleUrl("cncidr") },
  lancidr:{ type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "ipcidr", url: ruleUrl("lancidr") }
};

const groupBase = { interval: 300, timeout: 3000, url: CONFIG.SPEED_TEST_URL, lazy: true, "max-failed-times": 3, tolerance: 150 };

function main(config) {
  if (!config || typeof config !== "object") return config;
  console.log(`[Override] v0.7.1 | Proxies: ${config.proxies?.length || 0}`);

  // Core settings
  config.ipv6 = CONFIG.DNS_IPV6;
  config["tcp-concurrent"] = CONFIG.TCP_CONCURRENT;

  // TUN: auto-detect interface, strict route, hijack all DNS
  config.tun = { enable: true, stack: "system", "auto-route": true, "auto-detect-interface": true, "dns-hijack": ["any:53"], "strict-route": true, mtu: 1500 };

  // Sniffer: resolve bare IPs for accurate rule matching
  config.sniffer = { enable: true, "parse-pure-ip": true, "force-dns-mapping": true, sniff: { TLS: { ports: [443, 8443], "override-destination": true }, HTTP: { ports: [80, "8080-8880"], "override-destination": true }, QUIC: { ports: [443, 8443] } } };

  config.dns = dnsConfig;
  config["rule-providers"] = ruleProviders;

  // Group filters
  const safeFilter = `^(?!.*(${CONFIG.NODE_FILTER_KEYWORDS.join("|")})).*$`;
  const regions = { hk: "香港|HK|Hong Kong|🇭🇰", us: "美国|US|United States|🇺🇸", tw: "台湾|TW|Tai Wan|🇹🇼", jp: "日本|JP|Japan|🇯🇵", sg: "新加坡|SG|Singapore|🇸🇬" };
  const regionRe = (k) => `(?=.*(${regions[k]})).*$`;

  config["proxy-groups"] = [
    { ...groupBase, name: "节点选择", type: "select", proxies: ["延迟选优", "故障转移", "香港-自动", "美国-自动", "台湾-自动", "日本-自动", "新加坡-自动", "其他地区", "DIRECT"], "include-all": true, filter: safeFilter },
    { ...groupBase, name: "延迟选优", type: "url-test", "include-all": true, filter: safeFilter },
    { ...groupBase, name: "故障转移", type: "fallback", "include-all": true, filter: safeFilter },
    { name: "PikPak", type: "select", "include-all": true, proxies: ["新加坡-自动", "节点选择", "延迟选优", "故障转移", "香港-自动", "美国-自动", "台湾-自动", "日本-自动", "其他地区", "DIRECT"], filter: safeFilter },
    { ...groupBase, name: "香港-自动", type: "url-test", "include-all": true, filter: regionRe("hk") },
    { ...groupBase, name: "美国-自动", type: "url-test", "include-all": true, filter: regionRe("us") },
    { ...groupBase, name: "台湾-自动", type: "url-test", "include-all": true, filter: regionRe("tw") },
    { ...groupBase, name: "日本-自动", type: "url-test", "include-all": true, filter: regionRe("jp") },
    { ...groupBase, name: "新加坡-自动", type: "url-test", "include-all": true, filter: regionRe("sg") },
    { ...groupBase, name: "其他地区", type: "url-test", "include-all": true, filter: `^(?!.*(${Object.values(regions).join("|")}|${CONFIG.NODE_FILTER_KEYWORDS.join("|")})).*$` },
    { name: "全局直连", type: "select", proxies: ["DIRECT", "节点选择"] },
    { name: "全局拦截", type: "select", proxies: ["REJECT", "DIRECT"] },
    { name: "漏网之鱼", type: "select", proxies: ["节点选择", "延迟选优", "全局直连"] }
  ];

  config.rules = [
    "RULE-SET,reject,全局拦截", "RULE-SET,pikpak,PikPak", "RULE-SET,proxy,节点选择", "RULE-SET,gfw,节点选择",
    "RULE-SET,direct,全局直连", "RULE-SET,lancidr,全局直连,no-resolve", "RULE-SET,cncidr,全局直连,no-resolve",
    "IP-CIDR6,::1/128,DIRECT,no-resolve", "IP-CIDR6,fc00::/7,DIRECT,no-resolve", "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
    "GEOIP,LAN,全局直连,no-resolve", "GEOIP,CN,全局直连,no-resolve", "MATCH,漏网之鱼"
  ];

  // Node processing: filter invalid, enable UDP/xUDP safely
  if (config.proxies?.length) {
    config.proxies = config.proxies.filter(p => p?.name && !CONFIG.NODE_FILTER_KEYWORDS.some(k => p.name.includes(k)));
    config.proxies.forEach(p => {
      if (!p?.type) return;
      p.udp = true;
      if (CONFIG.XUDP_SAFE_MODE && /vmess|trojan|hysteria|hysteria2|tuic|shadowsocks/i.test(p.type)) p.xudp = true;
    });
  }

  console.log(`[Override] DNS:${dnsConfig.listen} | TUN:${config.tun?.stack} | Rules:${config.rules?.length}`);
  return config;
}

// ==========================================
// Clash.Meta Regional Extension Script
// Version: 1.1.11 (Final Release - No App Groups)
// Features: No Icons, English Group Names, Numbered Prefix, Fixed DNS & Speedtest
// Compatible: Sub-Store, Mihomo >= v1.18.0, Clash.Meta, Clash Verge, FlClash, Clash Mi
// ==========================================

const CONFIG = {
  DEBUG: false,
  DNS_PORT: 1053,
  FILTER_KEYWORDS: ["官网", "套餐", "流量", "异常", "剩余", "过期", "失效", "维护", "高倍", "倍率", "测试", "Test", "备用", "到期"],
  SPEED_TEST_URL: "https://www.google.com/generate_204",
  RULE_BASE_URL: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release",
  RULE_UPDATE_INTERVAL: 86400,
};

const filterRegex = new RegExp(CONFIG.FILTER_KEYWORDS.join("|"), "i");
const regionRegex = {
  hk: /香港|HK|Hong Kong/i,
  sg: /新加坡|SG|Singapore/i,
  jp: /日本|JP|Japan/i,
  us: /美国|US|United States/i,
  tw: /台湾|TW|Taiwan/i
};

function main(config) {
  if (!config || typeof config !== "object") return config;
  console.log("[Regional-Extension v1.1.11] Start processing...");

  // 1. Basic Settings
  config.mode = "rule";
  config.ipv6 = false;
  config["tcp-concurrent"] = true;
  config["log-level"] = "info";

  // 2. TUN & Sniffer
  config.tun = {
    enable: true,
    stack: "gvisor",
    "dns-hijack": [], // 关键：不强制劫持，防 DNS 泄露
    "auto-route": true,
    "auto-detect-interface": true
  };
  config.sniffer = {
    enable: true,
    "parse-pure-ip": true,
    "force-dns-mapping": true,
    sniff: {
      TLS: { ports: [443, 8443], "override-destination": true }
    }
  };

  // 3. DNS Configuration (核心修复：防污染 + 测速全绿 + 防泄露)
  config.dns = {
    enable: true,
    listen: `0.0.0.0:${CONFIG.DNS_PORT}`,
    ipv6: false,
    "respect-rules": true, // 灵魂配置：DNS 查询遵循路由规则
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter": [
      "+.lan", "+.local", "+.msftconnecttest.com", "+.msftncsi.com",
      "localhost.ptlogin2.qq.com", "localhost.sec.qq.com",
      "+.in-addr.arpa", "+.ip6.arpa", "time.*.com", "time.*.gov",
      "pool.ntp.org", "localhost.work.weixin.qq.com"
    ],
    "default-nameserver": ["223.5.5.5", "1.2.4.8"],
    nameserver: ["https://1.1.1.1/dns-query", "https://8.8.4.4/dns-query"],
    "proxy-server-nameserver": ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"],
    "direct-nameserver": ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"],
    "nameserver-policy": {
      "geosite:cn,private": ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"]
    }
  };

  // 4. Rule Providers (纯净版：移除 pikpak 和 telegramcidr)
  const ruleUrl = (n) => `${CONFIG.RULE_BASE_URL}/${n}.txt`;
  config["rule-providers"] = {
    reject: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("reject") },
    proxy: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("proxy") },
    direct: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("direct") },
    gfw: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("gfw") },
    cncidr: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "ipcidr", url: ruleUrl("cncidr") },
    lancidr: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "ipcidr", url: ruleUrl("lancidr") }
  };

  // 5. Proxy Filtering & Validation
  if (!Array.isArray(config.proxies) || config.proxies.length === 0) {
    console.warn("[Regional-Extension] No valid proxies found. Injecting safe fallback.");
    config["proxy-groups"] = [{ name: "[01] Proxy", type: "select", proxies: ["DIRECT"] }];
    config.rules = ["MATCH,DIRECT"];
    return config;
  }

  config.proxies = config.proxies.filter(p => {
    if (!p?.name || !p?.type) return false;
    if (filterRegex.test(p.name)) return false;
    p.udp = true; // 强制开启 UDP
    return true;
  });

  if (config.proxies.length === 0) {
    console.warn("[Regional-Extension] All nodes filtered out. Injecting safe fallback.");
    config["proxy-groups"] = [{ name: "[01] Proxy", type: "select", proxies: ["DIRECT"] }];
    config.rules = ["MATCH,DIRECT"];
    return config;
  }

  // 6. Proxy Groups (Numbered, No Icons, No App Groups)
  const safeFilter = `^(?!.*(${CONFIG.FILTER_KEYWORDS.join("|")})).*$`;
  const regionRe = (k) => regionRegex[k].source;
  const otherFilter = `^(?!.*(香港|HK|Hong Kong|新加坡|SG|Singapore|日本|JP|Japan|美国|US|United States|台湾|TW|Taiwan|${CONFIG.FILTER_KEYWORDS.join("|")})).*$`;

  const groups = [];

  // [01] Proxy (不包含应用组)
  groups.push({
    name: "[01] Proxy",
    type: "select",
    proxies: ["[02] AutoTest", "[03] Failover", "[04] HK", "[05] SG", "[06] JP", "[07] US", "[08] TW", "[09] Other", "DIRECT"]
  });

  // [02] AutoTest
  groups.push({
    name: "[02] AutoTest",
    type: "url-test",
    url: CONFIG.SPEED_TEST_URL,
    interval: 120,
    timeout: 3000,
    tolerance: 50,
    "include-all": true,
    filter: safeFilter
  });

  // [03] Failover
  groups.push({
    name: "[03] Failover",
    type: "fallback",
    url: CONFIG.SPEED_TEST_URL,
    interval: 120,
    timeout: 3000,
    "include-all": true,
    filter: safeFilter
  });

  // Regional Groups
  ["hk", "sg", "jp", "us", "tw"].forEach((k, i) => {
    const label = k.toUpperCase();
    groups.push({
      name: `[0${4 + i}] ${label}`,
      type: "url-test",
      url: CONFIG.SPEED_TEST_URL,
      interval: 300,
      timeout: 3000,
      tolerance: 100,
      "include-all": true,
      filter: regionRe(k)
    });
  });

  // [09] Other
  groups.push({
    name: "[09] Other",
    type: "url-test",
    url: CONFIG.SPEED_TEST_URL,
    interval: 300,
    timeout: 3000,
    tolerance: 100,
    "include-all": true,
    filter: otherFilter
  });

  // Basic Groups (重新编号)
  groups.push({ name: "[10] Direct", type: "select", proxies: ["DIRECT", "[01] Proxy"] });
  groups.push({ name: "[11] Reject", type: "select", proxies: ["REJECT", "DIRECT"] });
  groups.push({ name: "[12] CatchAll", type: "select", proxies: ["[01] Proxy", "[02] AutoTest", "DIRECT"] });
  groups.push({ name: "[13] GLOBAL", type: "select", proxies: ["DIRECT", "[01] Proxy", "[02] AutoTest"] });

  config["proxy-groups"] = groups;

  // 7. Rules (移除应用相关规则)
  let rules = [
    "DOMAIN-KEYWORD,stun,REJECT",
    "DOMAIN-KEYWORD,turn,REJECT",
    "AND,((NETWORK,UDP),(DST-PORT,19302)),REJECT",
    "AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,!CN)),REJECT",

    // Rule Sets
    "RULE-SET,reject,[11] Reject",
    "RULE-SET,proxy,[01] Proxy",
    "RULE-SET,gfw,[01] Proxy",
    "RULE-SET,direct,[10] Direct",
    "RULE-SET,lancidr,[10] Direct,no-resolve",
    "RULE-SET,cncidr,[10] Direct,no-resolve",
    "GEOIP,CN,[10] Direct,no-resolve",
    "MATCH,[12] CatchAll"
  ];
  config.rules = rules;

  // 8. Profile Storage
  config.profile = {
    "store-selected": true,
    "store-fake-ip": true
  };

  console.log(`[Regional-Extension v1.1.11] Success | Nodes: ${config.proxies.length} | Rules: ${rules.length} | Groups: ${groups.length}`);
  return config;
}

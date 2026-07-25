// ==========================================
// Clash.Meta Regional Extension Script
// Version: 1.1.16 (Final Stable - MTU Fix + Apple Whitelist)
// Aligned with: config v1.1.16 YAML
// Features: No Icons, English Group Names, Numbered Prefix [01]-[13],
//           Multi-Platform TUN (strict-route), DNS Anti-Leak, Fixed Speedtest
// Compatible: Sub-Store, Mihomo >= v1.18.0, Clash.Meta, Clash Verge, FlClash, Clash Mi
// ==========================================

const CONFIG = {
  DEBUG: false,
  DNS_PORT: 1053,
  MTU: 1500, // v1.1.16 修复：9000 巨型帧在移动/公网会丢包卡死，回归标准 1500
  // v1.1.16：过滤关键词含"重置"，剔除"距离下次重置..."等垃圾节点
  FILTER_KEYWORDS: ["官网", "套餐", "流量", "异常", "剩余", "过期", "失效", "维护", "高倍", "倍率", "测试", "Test", "备用", "到期", "重置"],
  // 实测最优测速地址（v1.1.11 验证全绿），勿改 gstatic/cloudflare
  SPEED_TEST_URL: "https://www.google.com/generate_204",
  RULE_BASE_URL: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release",
  RULE_UPDATE_INTERVAL: 86400,
};

const filterRegex = new RegExp(CONFIG.FILTER_KEYWORDS.join("|"), "i");
// v1.1.14 修复：US 正则支持 America/USA 命名
const regionRegex = {
  hk: /香港|HK|Hong Kong/i,
  sg: /新加坡|SG|Singapore/i,
  jp: /日本|JP|Japan/i,
  us: /美国|US|United States|America|USA/i,
  tw: /台湾|TW|Taiwan/i
};

function main(config) {
  if (!config || typeof config !== "object") return config;
  console.log("[Regional-Extension v1.1.16] Start processing...");

  // 1. Basic Settings
  config.mode = "rule";
  config.ipv6 = false;
  config["tcp-concurrent"] = true;
  config["log-level"] = "info";

  // 2. TUN Configuration (多端兼容核心)
  config.tun = {
    enable: true,
    stack: "gvisor",
    "strict-route": true,   // 路由层强制所有流量(含DNS)走TUN，PC防泄漏 + iOS不报错
    "dns-hijack": [],       // 保持空：iOS ClashMi 开 any:53 会启动失败，靠 strict-route 兜底
    "auto-route": true,
    "auto-detect-interface": true,
    mtu: CONFIG.MTU         // v1.1.16：标准 1500
  };

  // 3. Sniffer
  config.sniffer = {
    enable: true,
    "parse-pure-ip": true,
    "force-dns-mapping": true,
    sniff: {
      TLS: { ports: [443, 8443], "override-destination": true }
    }
  };

  // 4. DNS Configuration (防污染 + 测速全绿 + 防泄漏)
  config.dns = {
    enable: true,
    listen: `0.0.0.0:${CONFIG.DNS_PORT}`,
    ipv6: false,
    "respect-rules": true,  // 灵魂配置：DNS 查询遵循路由规则
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter": [
      "+.lan", "+.local",
      "+.apple.com", "+.icloud.com", "+.mzstatic.com", // v1.1.16：苹果服务不走 Fake-IP
      "+.msftconnecttest.com", "+.msftncsi.com",
      "localhost.ptlogin2.qq.com", "localhost.sec.qq.com",
      "+.in-addr.arpa", "+.ip6.arpa",
      "time.*.com", "time.*.gov", "pool.ntp.org",
      "localhost.work.weixin.qq.com"
    ],
    // 纯 IP 引导：IP 形式 DoH 无冷启动死锁问题
    "default-nameserver": ["223.5.5.5", "1.2.4.8"],
    // 保持国外：测速全绿的实测结论，勿改国内（v1.1.8/v1.1.10 全红教训）
    nameserver: ["https://1.1.1.1/dns-query", "https://8.8.4.4/dns-query"],
    "proxy-server-nameserver": ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"],
    "direct-nameserver": ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"],
    "nameserver-policy": {
      "geosite:cn,private": ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"]
    }
  };

  // 5. Rule Providers
  const ruleUrl = (n) => `${CONFIG.RULE_BASE_URL}/${n}.txt`;
  config["rule-providers"] = {
    reject:  { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("reject") },
    proxy:   { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("proxy") },
    direct:  { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("direct") },
    gfw:     { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "domain", url: ruleUrl("gfw") },
    cncidr:  { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "ipcidr", url: ruleUrl("cncidr") },
    lancidr: { type: "http", format: "yaml", interval: CONFIG.RULE_UPDATE_INTERVAL, behavior: "ipcidr", url: ruleUrl("lancidr") }
  };

  // 6. Proxy Filtering & Validation
  if (!Array.isArray(config.proxies) || config.proxies.length === 0) {
    console.warn("[Regional-Extension] No valid proxies found. Injecting safe fallback.");
    config["proxy-groups"] = [{ name: "[01] Proxy", type: "select", proxies: ["DIRECT"] }];
    config.rules = ["MATCH,DIRECT"];
    return config;
  }

  config.proxies = config.proxies.filter(p => {
    if (!p?.name || !p?.type) return false;
    if (filterRegex.test(p.name)) return false; // 剔除含关键词的垃圾节点
    p.udp = true; // 强制开启 UDP
    return true;
  });

  if (config.proxies.length === 0) {
    console.warn("[Regional-Extension] All nodes filtered out. Injecting safe fallback.");
    config["proxy-groups"] = [{ name: "[01] Proxy", type: "select", proxies: ["DIRECT"] }];
    config.rules = ["MATCH,DIRECT"];
    return config;
  }

  // 7. Proxy Groups (Numbered, No Icons, No App Groups)
  const safeFilter = `^(?!.*(${CONFIG.FILTER_KEYWORDS.join("|")})).*$`;
  const regionRe = (k) => regionRegex[k].source;
  const otherFilter = `^(?!.*(香港|HK|Hong Kong|新加坡|SG|Singapore|日本|JP|Japan|美国|US|United States|America|USA|台湾|TW|Taiwan|${CONFIG.FILTER_KEYWORDS.join("|")})).*$`;

  const groups = [];

  // [01] Proxy - 主策略组（include-all 显示全部节点 + 子策略组）
  groups.push({
    name: "[01] Proxy",
    type: "select",
    "include-all": true,
    proxies: ["[02] AutoTest", "[03] Failover", "[04] HK", "[05] SG", "[06] JP", "[07] US", "[08] TW", "[09] Other", "DIRECT"]
  });

  // [02] AutoTest - 自动测速
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

  // [03] Failover - 故障转移
  groups.push({
    name: "[03] Failover",
    type: "fallback",
    url: CONFIG.SPEED_TEST_URL,
    interval: 120,
    timeout: 3000,
    "include-all": true,
    filter: safeFilter
  });

  // [04]-[08] Regional Groups
  ["hk", "sg", "jp", "us", "tw"].forEach((k, i) => {
    groups.push({
      name: `[0${4 + i}] ${k.toUpperCase()}`,
      type: "url-test",
      url: CONFIG.SPEED_TEST_URL,
      interval: 300,
      timeout: 3000,
      tolerance: 100,
      "include-all": true,
      filter: regionRe(k)
    });
  });

  // [09] Other - 其他地区
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

  // [10]-[13] Basic Groups
  groups.push({ name: "[10] Direct",  type: "select", proxies: ["DIRECT", "[01] Proxy"] });
  groups.push({ name: "[11] Reject",  type: "select", proxies: ["REJECT", "DIRECT"] });
  groups.push({ name: "[12] CatchAll", type: "select", proxies: ["[01] Proxy", "[02] AutoTest", "DIRECT"] });
  groups.push({ name: "[13] GLOBAL",  type: "select", proxies: ["DIRECT", "[01] Proxy", "[02] AutoTest"] });

  config["proxy-groups"] = groups;

  // 8. Rules
  const rules = [
    "DOMAIN-KEYWORD,stun,REJECT",
    "DOMAIN-KEYWORD,turn,REJECT",
    "AND,((NETWORK,UDP),(DST-PORT,19302)),REJECT",
    "AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,!CN)),REJECT",
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

  // 9. Profile Storage
  config.profile = {
    "store-selected": true,
    "store-fake-ip": true
  };

  console.log(`[Regional-Extension v1.1.16] Success | Nodes: ${config.proxies.length} | Rules: ${rules.length} | Groups: ${groups.length}`);
  if (CONFIG.DEBUG) {
    console.log(`[Debug] MTU=${CONFIG.MTU} | SpeedTest=${CONFIG.SPEED_TEST_URL}`);
    console.log(`[Debug] Top 3:`, config.proxies.slice(0, 3).map(p => p.name).join(", "));
  }
  return config;
}

// Clash Override v0.9.2 | Stable Production Version

const CONFIG = {
  DNS_PORT: 1055,
  DNS_IPV6: true,
  FAKE_IP_V6: true,
  FAKE_IP_V6_RANGE: "fdfe:dcba:9876::/64",
  TCP_CONCURRENT: true,
  XUDP_SAFE_MODE: true,
  FILTER_KEYWORDS: ["官网","套餐","流量","异常","剩余","过期","失效","维护","高倍","倍率","测试","Test","备用"],
  SPEED_TEST_URL: "https://www.gstatic.com/generate_204",
  RULE_BASE_URL: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release",
  RULE_UPDATE_INTERVAL: 86400,
  BLOCK_QUIC: "overseas",
  AUTO_VALIDATE: true,
  ENABLE_PROCESS_RULES: true,
  DEBUG: false
};

const domesticNS = ["https://223.5.5.5/dns-query","https://doh.pub/dns-query"];
const foreignNS = ["https://1.1.1.1/dns-query","https://8.8.4.4/dns-query"];

const dnsConfig = {
  enable: true,
  listen: `0.0.0.0:${CONFIG.DNS_PORT}`,
  ipv6: CONFIG.DNS_IPV6,
  "enhanced-mode": "fake-ip",
  "fake-ip-range": "198.18.0.1/16",
  "fake-ip-ipv6": CONFIG.FAKE_IP_V6,
  "fake-ip-range6": CONFIG.FAKE_IP_V6_RANGE,
  "respect-rules": true,
  "fake-ip-filter": [
    "+.lan",
    "+.local",
    "+.msftconnecttest.com",
    "+.msftncsi.com",
    "localhost.ptlogin2.qq.com",
    "time.*.com"
  ],
  "default-nameserver": ["223.5.5.5","119.29.29.29","2400:3200::1"],
  nameserver: [...foreignNS],
  "proxy-server-nameserver": [...domesticNS],
  "direct-nameserver": [...domesticNS],
  "direct-nameserver-follow-policy": true,
  fallback: [...foreignNS],
  "fallback-filter": { geoip: true, "geoip-code": "CN" },
  "nameserver-policy": {
    "geosite:cn,private": domesticNS,
    "geosite:geolocation-!cn": foreignNS
  }
};

const ruleUrl = n => `${CONFIG.RULE_BASE_URL}/${n}.txt`;

const ruleProviders = {
  reject: { type:"http",format:"yaml",interval:CONFIG.RULE_UPDATE_INTERVAL,behavior:"domain",url:ruleUrl("reject") },
  pikpak: { type:"http",format:"yaml",interval:CONFIG.RULE_UPDATE_INTERVAL,behavior:"domain",url:ruleUrl("pikpak") },
  proxy:  { type:"http",format:"yaml",interval:CONFIG.RULE_UPDATE_INTERVAL,behavior:"domain",url:ruleUrl("proxy") },
  direct: { type:"http",format:"yaml",interval:CONFIG.RULE_UPDATE_INTERVAL,behavior:"domain",url:ruleUrl("direct") },
  gfw:    { type:"http",format:"yaml",interval:CONFIG.RULE_UPDATE_INTERVAL,behavior:"domain",url:ruleUrl("gfw") },
  cncidr: { type:"http",format:"yaml",interval:CONFIG.RULE_UPDATE_INTERVAL,behavior:"ipcidr",url:ruleUrl("cncidr") },
  lancidr:{ type:"http",format:"yaml",interval:CONFIG.RULE_UPDATE_INTERVAL,behavior:"ipcidr",url:ruleUrl("lancidr") }
};

function main(config) {
  if (!config || typeof config !== "object") return config;

  console.log(`[Override] v0.9.2 start`);

  config.ipv6 = CONFIG.DNS_IPV6;
  config["tcp-concurrent"] = CONFIG.TCP_CONCURRENT;

  config.tun = {
    enable: true,
    stack: "system",
    "auto-route": true,
    "auto-detect-interface": true,
    "dns-hijack": ["0.0.0.0:53"],
    "strict-route": true,
    mtu: 1500
  };

  config.sniffer = {
    enable: true,
    "parse-pure-ip": false,
    "force-dns-mapping": true,
    sniff: {
      TLS: { ports:[443,8443], "override-destination": true },
      HTTP:{ ports:[80,8080,8443], "override-destination": true },
      QUIC:{ ports:[443,8443] }
    }
  };

  config.dns = dnsConfig;
  config["rule-providers"] = ruleProviders;

  const baseGroup = { interval:300,timeout:5000,url:CONFIG.SPEED_TEST_URL,lazy:true,"max-failed-times":5,tolerance:200 };
  const safeFilter = `^(?!.*(${CONFIG.FILTER_KEYWORDS.join("|")})).*$`;

  config["proxy-groups"] = [
    { ...baseGroup,name:"节点选择",type:"select",proxies:["延迟选优","故障转移","香港-自动","美国-自动","台湾-自动","日本-自动","新加坡-自动","其他地区","DIRECT"],"include-all":true,filter:safeFilter },
    { ...baseGroup,name:"延迟选优",type:"url-test","include-all":true,filter:safeFilter },
    { ...baseGroup,name:"故障转移",type:"fallback","include-all":true,filter:safeFilter },
    { name:"PikPak",type:"select","include-all":true,proxies:["新加坡-自动","节点选择","DIRECT"],filter:safeFilter },
    { name:"Telegram",type:"select","include-all":true,proxies:["新加坡-自动","美国-自动","节点选择","DIRECT"],filter:safeFilter },

    { ...baseGroup,name:"香港-自动",type:"url-test","include-all":true,filter:"(?=.*(香港|HK|Hong Kong|🇭🇰)).*$" },
    { ...baseGroup,name:"美国-自动",type:"url-test","include-all":true,filter:"(?=.*(美国|US|United States|🇺🇸)).*$" },
    { ...baseGroup,name:"台湾-自动",type:"url-test","include-all":true,filter:"(?=.*(台湾|TW|Tai Wan|🇹🇼)).*$" },
    { ...baseGroup,name:"日本-自动",type:"url-test","include-all":true,filter:"(?=.*(日本|JP|Japan|🇯🇵)).*$" },
    { ...baseGroup,name:"新加坡-自动",type:"url-test","include-all":true,filter:"(?=.*(新加坡|SG|Singapore|🇸🇬)).*$" },
    { ...baseGroup,name:"其他地区",type:"url-test","include-all":true },

    { name:"全局直连",type:"select",proxies:["DIRECT","节点选择"] },
    { name:"全局拦截",type:"select",proxies:["REJECT","DIRECT"] },
    { name:"漏网之鱼",type:"select",proxies:["节点选择","延迟选优","全局直连"] }
  ];

  let rules = [];

  if (CONFIG.BLOCK_QUIC === "global") {
    rules.push("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT");
  } else if (CONFIG.BLOCK_QUIC === "overseas") {
    rules.push("AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,!CN)),REJECT");
  }

  if (CONFIG.ENABLE_PROCESS_RULES) {
    rules.push(
      "PROCESS-NAME,Telegram.exe,Telegram",
      "PROCESS-NAME,Updater.exe,Telegram",
      "PROCESS-NAME,PikPak.exe,PikPak",
      "PROCESS-NAME,com.pikpak.app,PikPak"
    );
  }

  rules.push(
    "RULE-SET,reject,全局拦截",
    "RULE-SET,pikpak,PikPak",

    "DOMAIN-SUFFIX,telegram.org,Telegram",
    "DOMAIN-SUFFIX,telegram.me,Telegram",
    "DOMAIN-KEYWORD,telegram,Telegram",
    "IP-CIDR,91.108.0.0/16,Telegram,no-resolve",
    "IP-CIDR,149.154.160.0/20,Telegram,no-resolve",
    "IP-CIDR6,2001:67c:4e8::/48,Telegram,no-resolve",

    "RULE-SET,proxy,节点选择",
    "RULE-SET,gfw,节点选择",

    "RULE-SET,direct,全局直连",
    "RULE-SET,lancidr,全局直连,no-resolve",
    "RULE-SET,cncidr,全局直连,no-resolve",

    "GEOIP,LAN,全局直连,no-resolve",
    "GEOIP,CN,全局直连,no-resolve",

    "MATCH,漏网之鱼"
  );

  config.rules = rules;

  if (!Array.isArray(config.proxies)) {
    console.warn("[Override] proxies invalid");
    return config;
  }

  config.proxies = config.proxies.filter(p => {
    if (!p?.name || !p?.type) return false;
    if (CONFIG.FILTER_KEYWORDS.some(k => p.name.includes(k))) return false;
    return true;
  });

  config.proxies.forEach(p => {
    p.udp = true;
    if (CONFIG.XUDP_SAFE_MODE && /vmess|trojan|hysteria|hysteria2|tuic/i.test(p.type)) {
      p.xudp = true;
    }
  });

  console.log(`[Override] Loaded | Nodes:${config.proxies.length} | DNS:${dnsConfig.listen}`);

  return config;
}

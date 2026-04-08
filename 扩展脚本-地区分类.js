// --- 1. DNS 深度防泄露配置 ---
const domesticNameservers = ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"];
const foreignNameservers = ["https://1.1.1.1/dns-query", "https://8.8.4.4/dns-query"];

const dnsConfig = {
  "enable": true,
  "listen": "0.0.0.0:1053",
  "ipv6": false,
  "enhanced-mode": "fake-ip",
  "fake-ip-range": "198.18.0.1/16",
  "respect-rules": true, 
  "fake-ip-filter": ["+.lan", "+.local", "+.msftconnecttest.com", "+.msftncsi.com", "localhost.ptlogin2.qq.com", "time.*.com"],
  "default-nameserver": ["223.5.5.5", "119.29.29.29"],
  "nameserver": [...foreignNameservers],
  "proxy-server-nameserver": [...domesticNameservers], 
  "nameserver-policy": {
    "geosite:cn,private": domesticNameservers,
    "geosite:geolocation-!cn": foreignNameservers
  }
};

// --- 2. 规则集定义 ---
const ruleProviderCommon = { "type": "http", "format": "yaml", "interval": 86400 };
const ruleProviders = {
  "reject": { ...ruleProviderCommon, "behavior": "domain", "url": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt" },
  "pikpak": { ...ruleProviderCommon, "behavior": "domain", "url": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/pikpak.txt" },
  "proxy": { ...ruleProviderCommon, "behavior": "domain", "url": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt" },
  "direct": { ...ruleProviderCommon, "behavior": "domain", "url": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt" },
  "gfw": { ...ruleProviderCommon, "behavior": "domain", "url": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt" },
  "cncidr": { ...ruleProviderCommon, "behavior": "ipcidr", "url": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt" },
  "lancidr": { ...ruleProviderCommon, "behavior": "ipcidr", "url": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt" }
};

// --- [策略组通用配置] ---
const groupBaseOption = { 
  "interval": 300, 
  "timeout": 3000,          // 节点秒开：3秒超时，快速判定不可用节点
  "url": "https://www.google.com/generate_204", 
  "lazy": true, 
  "max-failed-times": 3 
};

function main(config) {
  if (!config) return config;

  // TUN 模式强化 (针对 FlClash 等软件)
  config["tun"] = {
    "enable": true,
    "stack": "system",
    "auto-route": true,
    "auto-detect-interface": true,
    "dns-hijack": ["any:53"],
    "strict-route": true, 
    "mtu": 1500
  };

  // 开启嗅探
  config["sniffer"] = {
    "enable": true,
    "sniff": {
      "TLS": { "ports": [443, 8443] },
      "HTTP": { "ports": [80, "8080-8880"], "override-destination": true }
    }
  };

  config["dns"] = dnsConfig;
  config["rule-providers"] = ruleProviders;

  config["proxy-groups"] = [
    {
      ...groupBaseOption,
      "name": "节点选择",
      "type": "select",
      "proxies": ["延迟选优", "故障转移", "香港-自动", "美国-自动", "台湾-自动", "日本-自动", "新加坡-自动", "其他地区", "DIRECT"],
      "include-all": true,
      "filter": "^(?!.*(官网|套餐|流量|异常|剩余)).*$"
    },
    { 
      ...groupBaseOption, 
      "name": "延迟选优", 
      "type": "url-test", 
      "tolerance": 150,     // 容差 150ms，防止网络微小波动导致的频繁跳点
      "include-all": true, 
      "filter": "^(?!.*(官网|套餐|流量|异常|剩余)).*$" 
    },
    { ...groupBaseOption, "name": "故障转移", "type": "fallback", "include-all": true, "filter": "^(?!.*(官网|套餐|流量|异常|剩余)).*$" },
    {
      "name": "PikPak",
      "type": "select",
      "include-all": true,
      "proxies": ["新加坡-自动", "节点选择", "延迟选优", "故障转移", "香港-自动", "美国-自动", "台湾-自动", "日本-自动", "其他地区", "DIRECT"],
      "filter": "^(?!.*(官网|套餐|流量|异常|剩余)).*$"
    },
    { ...groupBaseOption, "name": "香港-自动", "type": "url-test", "include-all": true, "filter": "(?=.*(香港|HK|Hong Kong|🇭🇰)).*$" },
    { ...groupBaseOption, "name": "美国-自动", "type": "url-test", "include-all": true, "filter": "(?=.*(美国|US|United States|🇺🇸)).*$" },
    { ...groupBaseOption, "name": "台湾-自动", "type": "url-test", "include-all": true, "filter": "(?=.*(台湾|TW|Tai Wan|🇹🇼)).*$" },
    { ...groupBaseOption, "name": "日本-自动", "type": "url-test", "include-all": true, "filter": "(?=.*(日本|JP|Japan|🇯🇵)).*$" },
    { ...groupBaseOption, "name": "新加坡-自动", "type": "url-test", "include-all": true, "filter": "(?=.*(新加坡|SG|Singapore|🇸🇬)).*$" },
    {
      ...groupBaseOption,
      "name": "其他地区",
      "type": "url-test",
      "include-all": true,
      "filter": "^(?!.*(香港|HK|Hong Kong|🇭🇰|美国|US|United States|🇺🇸|台湾|TW|Tai Wan|🇹🇼|日本|JP|Japan|🇯🇵|新加坡|SG|Singapore|🇸🇬|官网|套餐|流量|异常|剩余)).*$"
    },
    { "name": "全局直连", "type": "select", "proxies": ["DIRECT", "节点选择"] },
    { "name": "全局拦截", "type": "select", "proxies": ["REJECT", "DIRECT"] },
    { "name": "漏网之鱼", "type": "select", "proxies": ["节点选择", "延迟选优", "全局直连"] }
  ];

  config["rules"] = [
    "RULE-SET,reject,全局拦截",
    "RULE-SET,pikpak,PikPak",
    "RULE-SET,proxy,节点选择",
    "RULE-SET,gfw,节点选择",
    "RULE-SET,direct,全局直连",
    "RULE-SET,lancidr,全局直连,no-resolve",
    "RULE-SET,cncidr,全局直连,no-resolve",
    "GEOIP,LAN,全局直连,no-resolve",
    "GEOIP,CN,全局直连,no-resolve",
    "MATCH,漏网之鱼"
  ];

  if (config.proxies && Array.isArray(config.proxies)) {
    config.proxies.forEach(p => { if (p) p.udp = true; });
  }

  return config;
}

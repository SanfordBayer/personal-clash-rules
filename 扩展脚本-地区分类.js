// 国内 DNS 
const domesticNameservers = [
  "https://223.5.5.5/dns-query", // 阿里
  "https://doh.pub/dns-query"    // 腾讯
];
// 国外 DNS
const foreignNameservers = [
  "https://1.1.1.1/dns-query",
  "https://8.8.4.4/dns-query",
  "https://208.67.222.222/dns-query"
];

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
    "geosite:private,cn": domesticNameservers
  }
};

const ruleProviderCommon = { "type": "http", "format": "yaml", "interval": 86400 };

const ruleProviders = {
  "reject": { ...ruleProviderCommon, "behavior": "domain", "url": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt" },
  "proxy": { ...ruleProviderCommon, "behavior": "domain", "url": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt" },
  "direct": { ...ruleProviderCommon, "behavior": "domain", "url": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt" },
  "gfw": { ...ruleProviderCommon, "behavior": "domain", "url": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt" },
  "cncidr": { ...ruleProviderCommon, "behavior": "ipcidr", "url": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt" },
  "lancidr": { ...ruleProviderCommon, "behavior": "ipcidr", "url": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt" }
};

// 代理组通用模板
const groupBaseOption = {
  "interval": 300,
  "timeout": 3000,
  "url": "https://www.google.com/generate_204",
  "lazy": true,
  "max-failed-times": 3
};

function main(config) {
  // 1. 注入 DNS 配置
  config["dns"] = dnsConfig;

  // 2. 注入 规则集
  config["rule-providers"] = ruleProviders;

  // 3. 定义 代理组
  config["proxy-groups"] = [
    {
      ...groupBaseOption,
      "name": "节点选择",
      "type": "select",
      // 【修复说明】：将原来的 "全局直连" 替换为底层的 "DIRECT"，打破死循环
      "proxies": ["延迟选优", "故障转移", "香港-自动", "美国-自动", "台湾-自动", "日本-自动", "新加坡-自动", "韩国-自动", "DIRECT"],
      "include-all": true,
      "filter": "^(?!.*(官网|套餐|流量|异常|剩余)).*$"
    },
    {
      ...groupBaseOption,
      "name": "延迟选优",
      "type": "url-test",
      "tolerance": 100,
      "include-all": true,
      "filter": "^(?!.*(官网|套餐|流量|异常|剩余)).*$"
    },
    {
      ...groupBaseOption,
      "name": "故障转移",
      "type": "fallback",
      "include-all": true,
      "filter": "^(?!.*(官网|套餐|流量|异常|剩余)).*$"
    },
    // --- 地区自动选择组 ---
    {
      ...groupBaseOption,
      "name": "香港-自动",
      "type": "url-test",
      "include-all": true,
      "filter": "(?=.*(香港|HK|Hong Kong|🇭🇰)).*$"
    },
    {
      ...groupBaseOption,
      "name": "美国-自动",
      "type": "url-test",
      "include-all": true,
      "filter": "(?=.*(美国|US|United States|🇺🇸)).*$"
    },
    {
      ...groupBaseOption,
      "name": "台湾-自动",
      "type": "url-test",
      "include-all": true,
      "filter": "(?=.*(台湾|TW|Tai Wan|🇹🇼)).*$"
    },
    {
      ...groupBaseOption,
      "name": "日本-自动",
      "type": "url-test",
      "include-all": true,
      "filter": "(?=.*(日本|JP|Japan|🇯🇵)).*$"
    },
    {
      ...groupBaseOption,
      "name": "新加坡-自动",
      "type": "url-test",
      "include-all": true,
      "filter": "(?=.*(新加坡|SG|Singapore|🇸🇬)).*$"
    },
    {
      ...groupBaseOption,
      "name": "韩国-自动",
      "type": "url-test",
      "include-all": true,
      "filter": "(?=.*(韩国|KR|Korea|🇰🇷)).*$"
    },
    // --- 基础状态组 ---
    {
      "name": "全局直连",
      "type": "select",
      "proxies": ["DIRECT", "节点选择"]
    },
    {
      "name": "全局拦截",
      "type": "select",
      "proxies": ["REJECT", "DIRECT"]
    },
    {
      "name": "漏网之鱼",
      "type": "select",
      "proxies": ["节点选择", "延迟选优", "全局直连"]
    }
  ];

  // 4. 定义 规则逻辑 
  config["rules"] = [
    "RULE-SET,reject,全局拦截",
    "RULE-SET,proxy,节点选择",
    "RULE-SET,gfw,节点选择",
    "RULE-SET,direct,全局直连",
    "RULE-SET,lancidr,全局直连,no-resolve",
    "RULE-SET,cncidr,全局直连,no-resolve",
    "GEOIP,LAN,全局直连,no-resolve",
    "GEOIP,CN,全局直连,no-resolve",
    "MATCH,漏网之鱼"
  ];

  // 5. 开启所有节点的 UDP 支持
  if (config["proxies"]) {
    config["proxies"].forEach(p => p.udp = true);
  }

  return config;
}

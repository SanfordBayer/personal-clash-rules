// --- 1. DNS 配置 ---
const domesticNameservers = [
  "https://223.5.5.5/dns-query", 
  "https://doh.pub/dns-query"
];
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

// --- 2. 规则集配置 (Rule Providers) ---
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

const groupBaseOption = {
  "interval": 300,
  "timeout": 3000,
  "url": "https://www.google.com/generate_204",
  "lazy": true,
  "max-failed-times": 3
};

// --- 3. 主函数 (Main) ---
function main(config) {
  if (!config) return config;

  // 注入 DNS 和 规则集
  config["dns"] = dnsConfig;
  config["rule-providers"] = ruleProviders;

  // 注入策略组
  config["proxy-groups"] = [
    // A. 核心控制组
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

    // B. 业务专用组 (PikPak) - 包含全部节点供手动切换
    {
      "name": "Pikpak",
      "type": "select",
      "include-all": true,
      "proxies": ["新加坡-自动", "节点选择", "延迟选优", "故障转移", "香港-自动", "美国-自动", "台湾-自动", "日本-自动", "其他地区", "DIRECT"],
      "filter": "^(?!.*(官网|套餐|流量|异常|剩余)).*$"
    },

    // C. 地区分类自动测速组
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

    // D. 基础分流组
    { "name": "全局直连", "type": "select", "proxies": ["DIRECT", "节点选择"] },
    { "name": "全局拦截", "type": "select", "proxies": ["REJECT", "DIRECT"] },
    { "name": "漏网之鱼", "type": "select", "proxies": ["节点选择", "延迟选优", "全局直连"] }
  ];

  // 注入分流规则 (顺序严密)
  config["rules"] = [
    "RULE-SET,reject,全局拦截",
    "RULE-SET,pikpak,Pikpak", // PikPak 规则置顶挂载
    "RULE-SET,proxy,节点选择",
    "RULE-SET,gfw,节点选择",
    "RULE-SET,direct,全局直连",
    "RULE-SET,lancidr,全局直连,no-resolve",
    "RULE-SET,cncidr,全局直连,no-resolve",
    "GEOIP,LAN,全局直连,no-resolve",
    "GEOIP,CN,全局直连,no-resolve",
    "MATCH,漏网之鱼"
  ];

  // 全局节点 UDP 开启
  if (config.proxies && Array.isArray(config.proxies)) {
    config.proxies.forEach(p => {
      if (p) p.udp = true;
    });
  }

  return config;
}

/**
 * Clash Meta (Mihomo) 四端全兼容终极覆写脚本 v1.5.7
 * 特性：
 * 1. 自动清洗残缺的 mieru 节点与空名节点，防止内核解析报错
 * 2. 完整接管 DNS / TUN / Sniffer，含 Apple 推送与系统服务保护
 * 3. 全量 AI（含国内大模型国际版）走 [09] AI，Google/YouTube/Telegram 精准分流
 * 4. 兼容 Android / iOS / macOS / Windows 四端
 */

function main(config) {
  // 1. 节点安全清洗：自动剔除名字为空或缺失必填参数的残缺 mieru 节点
  if (Array.isArray(config.proxies)) {
    config.proxies = config.proxies.filter((p) => {
      if (!p || !p.name || String(p.name).trim() === "") return false;
      if (p.type === "mieru") {
        if (!p.username || !p.password || !p.transport) return false;
      }
      return true;
    });
  }

  // 2. 基础全局配置覆写
  Object.assign(config, {
    "mixed-port": 7890,
    "socks-port": 7891,
    "allow-lan": true,
    "bind-address": "*",
    "mode": "rule",
    "log-level": "info",
    "ipv6": false,
    "tcp-concurrent": true,
    "unified-delay": true,
    "keep-alive-interval": 30,
    "find-process-mode": "always",
    "profile": {
      "store-selected": true,
      "store-fake-ip": true
    },
    "tun": {
      "enable": true,
      "stack": "mixed",
      "strict-route": true,
      "dns-hijack": ["any:53", "tcp://any:53", "any:853"],
      "auto-route": true,
      "auto-detect-interface": true,
      "mtu": 1500
    },
    "sniffer": {
      "enable": true,
      "parse-pure-ip": true,
      "override-destination": true,
      "sniff": {
        "TLS": { "ports": [443, 8443] },
        "HTTP": { "ports": [80, "8080-8088"] },
        "QUIC": { "ports": [443, 8443] }
      },
      "skip-domain": [
        "Mijia Cloud",
        "+.push.apple.com",
        "+.apple.com"
      ]
    },
    "dns": {
      "enable": true,
      "listen": "0.0.0.0:1053",
      "ipv6": false,
      "respect-rules": true,
      "enhanced-mode": "fake-ip",
      "fake-ip-range": "198.18.0.1/16",
      "fake-ip-filter": [
        "+.lan",
        "+.local",
        "+.msftconnecttest.com",
        "+.msftncsi.com",
        "time.*.com",
        "time.*.gov",
        "time.*.apple.com",
        "pool.ntp.org",
        "+.push.apple.com",
        "mesu.apple.com",
        "swscan.apple.com",
        "swquery.apple.com"
      ],
      "default-nameserver": ["223.5.5.5", "119.29.29.29"],
      "nameserver": ["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"],
      "proxy-server-nameserver": ["https://223.5.5.5/dns-query"],
      "direct-nameserver": ["https://223.5.5.5/dns-query"]
    }
  });

  // 通用排除过滤正则（剔除套餐到期说明与残缺协议）
  const commonExcludeFilter = "^(?i)(?!.*(官网|套餐|流量|异常|剩余|过期|失效|维护|高倍|倍率|测试|Test|备用|到期|重置)).*$";

  // 3. 策略组覆写
  config["proxy-groups"] = [
    {
      name: "[01] Proxy",
      type: "select",
      "include-all": true,
      proxies: ["[02] AutoTest", "[03] Failover", "[10] 香港", "[11] 新加坡", "[12] 日本", "[13] 美国", "[14] 台湾", "[15] 其他", "DIRECT"]
    },
    {
      name: "[02] AutoTest",
      type: "url-test",
      url: "https://www.google.com/generate_204",
      interval: 120,
      tolerance: 50,
      "include-all": true,
      filter: commonExcludeFilter
    },
    {
      name: "[03] Failover",
      type: "fallback",
      url: "https://www.google.com/generate_204",
      interval: 120,
      "include-all": true,
      filter: commonExcludeFilter
    },
    {
      name: "[04] Google",
      type: "select",
      proxies: ["[01] Proxy", "[02] AutoTest", "[11] 新加坡", "[13] 美国", "[12] 日本", "DIRECT"],
      "include-all": true
    },
    {
      name: "[05] Telegram",
      type: "url-test",
      url: "https://www.google.com/generate_204",
      interval: 300,
      tolerance: 100,
      "include-all": true,
      filter: commonExcludeFilter
    },
    {
      name: "[06] PikPak",
      type: "url-test",
      url: "https://www.google.com/generate_204",
      interval: 300,
      tolerance: 100,
      "include-all": true,
      filter: commonExcludeFilter
    },
    {
      name: "[07] Twitter",
      type: "url-test",
      url: "https://www.google.com/generate_204",
      interval: 120,
      tolerance: 50,
      "include-all": true,
      filter: commonExcludeFilter
    },
    {
      name: "[08] YouTube",
      type: "url-test",
      url: "https://www.google.com/generate_204",
      interval: 120,
      tolerance: 50,
      "include-all": true,
      filter: commonExcludeFilter
    },
    {
      name: "[09] AI",
      type: "url-test",
      url: "https://www.google.com/generate_204",
      interval: 120,
      tolerance: 50,
      "include-all": true,
      filter: "(?i)us|jp|sg|tw|美国|日本|新加坡|台湾|United States|Japan|Singapore|Taiwan"
    },
    {
      name: "[10] 香港",
      type: "url-test",
      url: "https://www.google.com/generate_204",
      interval: 300,
      tolerance: 100,
      "include-all": true,
      filter: "(?i)hk|香港|Hong Kong"
    },
    {
      name: "[11] 新加坡",
      type: "url-test",
      url: "https://www.google.com/generate_204",
      interval: 300,
      tolerance: 100,
      "include-all": true,
      filter: "(?i)sg|新加坡|Singapore"
    },
    {
      name: "[12] 日本",
      type: "url-test",
      url: "https://www.google.com/generate_204",
      interval: 300,
      tolerance: 100,
      "include-all": true,
      filter: "(?i)jp|日本|Japan"
    },
    {
      name: "[13] 美国",
      type: "url-test",
      url: "https://www.google.com/generate_204",
      interval: 300,
      tolerance: 100,
      "include-all": true,
      filter: "(?i)us|美国|United States|America"
    },
    {
      name: "[14] 台湾",
      type: "url-test",
      url: "https://www.google.com/generate_204",
      interval: 300,
      tolerance: 100,
      "include-all": true,
      filter: "(?i)tw|台湾|Taiwan"
    },
    {
      name: "[15] 其他",
      type: "url-test",
      url: "https://www.google.com/generate_204",
      interval: 300,
      tolerance: 100,
      "include-all": true,
      filter: "^(?i)(?!.*(hk|sg|jp|us|tw|香港|新加坡|日本|美国|台湾|官网|套餐|流量|到期|剩余)).*$"
    },
    { name: "[16] Direct", type: "select", proxies: ["DIRECT", "[01] Proxy"] },
    { name: "[17] Reject", type: "select", proxies: ["REJECT", "DIRECT"] },
    { name: "[18] CatchAll", type: "select", proxies: ["[01] Proxy", "[02] AutoTest", "DIRECT"] },
    { name: "[19] GLOBAL", type: "select", proxies: ["DIRECT", "[01] Proxy", "[02] AutoTest"] },
    { name: "[20] Agents", type: "select", proxies: ["[09] AI", "[01] Proxy", "[02] AutoTest", "DIRECT"] }
  ];

  // 4. 外部规则集覆写
  config["rule-providers"] = {
    reject: { type: "http", format: "yaml", interval: 86400, behavior: "domain", url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt" },
    proxy: { type: "http", format: "yaml", interval: 86400, behavior: "domain", url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt" },
    direct: { type: "http", format: "yaml", interval: 86400, behavior: "domain", url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt" },
    apple: { type: "http", format: "yaml", interval: 86400, behavior: "domain", url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt" },
    icloud: { type: "http", format: "yaml", interval: 86400, behavior: "domain", url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt" },
    gfw: { type: "http", format: "yaml", interval: 86400, behavior: "domain", url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt" },
    cncidr: { type: "http", format: "yaml", interval: 86400, behavior: "ipcidr", url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt" },
    lancidr: { type: "http", format: "yaml", interval: 86400, behavior: "ipcidr", url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt" },
    telegram: { type: "http", format: "yaml", interval: 86400, behavior: "classical", url: "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Telegram/Telegram.yaml" },
    telegramcidr: { type: "http", format: "yaml", interval: 86400, behavior: "ipcidr", url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt" },
    twitter: { type: "http", format: "yaml", interval: 86400, behavior: "classical", url: "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Twitter/Twitter.yaml" },
    youtube: { type: "http", format: "yaml", interval: 86400, behavior: "classical", url: "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/YouTube/YouTube.yaml" },
    google: { type: "http", format: "yaml", interval: 86400, behavior: "classical", url: "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Google/Google.yaml" },
    pikpak: { type: "http", format: "yaml", interval: 86400, behavior: "classical", url: "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/PikPak/PikPak.yaml" },
    ai: { type: "http", format: "yaml", interval: 86400, behavior: "classical", url: "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/OpenAI/OpenAI.yaml" }
  };

  // 5. 分流规则覆写
  config["rules"] = [
    // 桌面端与 Android 进程规则（iOS 自动忽略）
    "PROCESS-NAME,Antigravity,[20] Agents",
    "PROCESS-NAME,Cursor,[20] Agents",
    "PROCESS-NAME,Cursor Helper,[20] Agents",
    "PROCESS-NAME,Windsurf,[20] Agents",
    "PROCESS-NAME,Claude,[20] Agents",
    "PROCESS-NAME,Claude Helper,[20] Agents",
    "PROCESS-NAME,Codex,[20] Agents",
    "PROCESS-NAME,Hermes,[20] Agents",
    "PROCESS-NAME,hermes.exe,[20] Agents",
    "PROCESS-NAME,com.google.android.apps.bard,[09] AI",
    "PROCESS-NAME,com.openai.chatgpt,[09] AI",

    // AI 平台全量域名规则（全量走 [09] AI 或 [20] Agents）
    "DOMAIN-KEYWORD,antigravity,[09] AI",
    "DOMAIN-KEYWORD,hermes,[09] AI",
    "DOMAIN-SUFFIX,cursor.sh,[20] Agents",
    "DOMAIN-SUFFIX,cursor.com,[20] Agents",
    "DOMAIN-SUFFIX,codeium.com,[20] Agents",
    "DOMAIN-SUFFIX,windsurf.com,[20] Agents",
    "DOMAIN-SUFFIX,z.ai,[09] AI",
    "DOMAIN-SUFFIX,bigmodel.cn,[09] AI",
    "DOMAIN-SUFFIX,zhipuai.cn,[09] AI",
    "DOMAIN-SUFFIX,qwen.ai,[09] AI",
    "DOMAIN-SUFFIX,qwenlm.ai,[09] AI",
    "DOMAIN-SUFFIX,tongyi.aliyun.com,[09] AI",
    "DOMAIN-SUFFIX,dashscope.aliyuncs.com,[09] AI",
    "DOMAIN-SUFFIX,dashscope.aliyun.com,[09] AI",
    "DOMAIN-SUFFIX,modelscope.cn,[09] AI",
    "DOMAIN-SUFFIX,moonshot.cn,[09] AI",
    "DOMAIN-SUFFIX,kimi.com,[09] AI",
    "DOMAIN-SUFFIX,minimax.chat,[09] AI",
    "DOMAIN-SUFFIX,doubao.com,[09] AI",
    "DOMAIN-SUFFIX,volcengine.com,[09] AI",
    "DOMAIN-SUFFIX,qianfan.baidu.com,[09] AI",
    "DOMAIN-SUFFIX,baichuan-ai.com,[09] AI",
    "DOMAIN-SUFFIX,01.ai,[09] AI",
    "DOMAIN-SUFFIX,xfyun.cn,[09] AI",
    "DOMAIN-SUFFIX,gemini.google.com,[09] AI",
    "DOMAIN-SUFFIX,generativelanguage.googleapis.com,[09] AI",
    "DOMAIN-SUFFIX,aistudio.google.com,[09] AI",
    "DOMAIN-SUFFIX,makersuite.google.com,[09] AI",
    "DOMAIN-SUFFIX,openai.com,[09] AI",
    "DOMAIN-SUFFIX,chatgpt.com,[09] AI",
    "DOMAIN-SUFFIX,oaistatic.com,[09] AI",
    "DOMAIN-SUFFIX,oaiusercontent.com,[09] AI",
    "DOMAIN-SUFFIX,claude.ai,[09] AI",
    "DOMAIN-SUFFIX,anthropic.com,[09] AI",
    "DOMAIN-SUFFIX,x.ai,[09] AI",
    "DOMAIN-SUFFIX,grok.com,[09] AI",
    "DOMAIN-SUFFIX,perplexity.ai,[09] AI",
    "DOMAIN-SUFFIX,deepseek.com,[09] AI",

    // 流媒体与社交网站（排在 Google 之前）
    "PROCESS-NAME,com.google.android.youtube,[08] YouTube",
    "DOMAIN-SUFFIX,youtube.com,[08] YouTube",
    "DOMAIN-SUFFIX,youtu.be,[08] YouTube",
    "DOMAIN-SUFFIX,googlevideo.com,[08] YouTube",
    "DOMAIN-SUFFIX,ytimg.com,[08] YouTube",
    "DOMAIN-SUFFIX,youtubei.googleapis.com,[08] YouTube",
    "DOMAIN-SUFFIX,x.com,[07] Twitter",
    "DOMAIN-SUFFIX,twitter.com,[07] Twitter",
    "DOMAIN-SUFFIX,twimg.com,[07] Twitter",
    "DOMAIN-SUFFIX,t.me,[05] Telegram",
    "DOMAIN-SUFFIX,tdesktop.com,[05] Telegram",

    // Google 核心服务（兼顾 Android 包名与 iOS/macOS 全量域名）
    "PROCESS-NAME,com.android.vending,[04] Google",
    "PROCESS-NAME,com.google.android.gms,[04] Google",
    "PROCESS-NAME,com.google.android.gsf,[04] Google",
    "PROCESS-NAME,com.google.android.googlequicksearchbox,[04] Google",
    "DOMAIN-SUFFIX,google.com,[04] Google",
    "DOMAIN-SUFFIX,googleapis.com,[04] Google",
    "DOMAIN-SUFFIX,gstatic.com,[04] Google",
    "DOMAIN-SUFFIX,ggpht.com,[04] Google",
    "DOMAIN-SUFFIX,googleusercontent.com,[04] Google",
    "DOMAIN-SUFFIX,gmail.com,[04] Google",
    "DOMAIN-SUFFIX,1e100.net,[04] Google",
    "DOMAIN-SUFFIX,gvt1.com,[04] Google",
    "DOMAIN-SUFFIX,gvt2.com,[04] Google",
    "DOMAIN-SUFFIX,gvt3.com,[04] Google",
    "DOMAIN-SUFFIX,appspot.com,[04] Google",
    "DOMAIN-SUFFIX,firebaseio.com,[04] Google",
    "DOMAIN-KEYWORD,google,[04] Google",

    // 外部规则集匹配
    "RULE-SET,reject,[17] Reject",
    "RULE-SET,ai,[09] AI",
    "RULE-SET,youtube,[08] YouTube",
    "RULE-SET,google,[04] Google",
    "RULE-SET,telegram,[05] Telegram",
    "RULE-SET,telegramcidr,[05] Telegram,no-resolve",
    "RULE-SET,twitter,[07] Twitter",
    "RULE-SET,pikpak,[06] PikPak",
    "RULE-SET,icloud,[16] Direct",
    "RULE-SET,apple,[16] Direct",
    "RULE-SET,proxy,[01] Proxy",
    "RULE-SET,gfw,[01] Proxy",
    "RULE-SET,direct,[16] Direct",
    "RULE-SET,lancidr,[16] Direct,no-resolve",
    "RULE-SET,cncidr,[16] Direct,no-resolve",

    // 兜底规则
    "GEOIP,LAN,[16] Direct,no-resolve",
    "GEOIP,CN,[16] Direct,no-resolve",
    "MATCH,[18] CatchAll"
  ];

  return config;
}

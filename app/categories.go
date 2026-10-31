package main

// 内置域名分类库与 OUI 厂商库。
//
// 分类键与色值严格按 docs/api.md §8（前端依赖，禁止改动）：
//   video/game/social/web/download/mail/cloud/other
// 黑名单域名单独用 BlockKind 标记（gambling 赌博 / porn 色情 / mining 矿池），
// 分类仍归入 other，用于安全事件与封堵建议。
//
// 匹配规则：对域名做"最长后缀匹配"，例如 game.bilibili.com 先命中 bilibili.com。

import "strings"

// Category 分类元信息。
type Category struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Color string `json:"color"`
}

// Categories 固定 8 项且顺序固定（api.md §8）。
var Categories = []Category{
	{"video", "视频流媒体", "#22d3ee"},
	{"game", "游戏", "#a78bfa"},
	{"social", "社交聊天", "#f472b6"},
	{"web", "网页浏览", "#38bdf8"},
	{"download", "下载更新", "#fbbf24"},
	{"mail", "邮件", "#34d399"},
	{"cloud", "云盘存储", "#2dd4bf"},
	{"other", "其他", "#94a3b8"},
}

var catByKey = map[string]Category{}

// catOrder 分类索引，用于稳定排序。
var catOrder = map[string]int{}

func init() {
	for i, c := range Categories {
		catByKey[c.Key] = c
		catOrder[c.Key] = i
	}
}

func categoryLabel(key string) string {
	if c, ok := catByKey[key]; ok {
		return c.Label
	}
	return "其他"
}

func categoryColor(key string) string {
	if c, ok := catByKey[key]; ok {
		return c.Color
	}
	return "#94a3b8"
}

func validCategory(key string) bool {
	_, ok := catByKey[key]
	return ok
}

// domainRule 一条后缀域名规则。
type domainRule struct {
	Domain    string
	Cat       string
	Label     string
	BlockKind string // 非空 = 黑名单：gambling/porn/mining
}

var (
	domainIndex  = map[string]domainRule{} // 后缀 -> 规则
	catDomains   = map[string][]string{}   // 分类 -> 域名列表（供策略按分类封堵）
	blockDomains = map[string][]string{}   // 黑名单类别 -> 域名列表
)

// addGroup 注册一组同品牌的域名。
func addGroup(cat, label string, domains ...string) {
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		domainIndex[d] = domainRule{Domain: d, Cat: cat, Label: label}
		catDomains[cat] = append(catDomains[cat], d)
	}
}

// addBlocked 注册黑名单域名（归入 other 分类，带 BlockKind）。
func addBlocked(kind string, domains ...string) {
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		domainIndex[d] = domainRule{Domain: d, Cat: "other", Label: d, BlockKind: kind}
		blockDomains[kind] = append(blockDomains[kind], d)
	}
}

func init() {
	// ---------------- 视频流媒体 ----------------
	addGroup("video", "哔哩哔哩", "bilibili.com", "b23.tv", "bilivideo.com", "bilivideo.cn", "hdslb.com", "biliapi.net", "biliapi.com")
	addGroup("video", "抖音", "douyin.com", "douyinvod.com", "douyinpic.com", "douyincdn.com", "iesdouyin.com", "amemv.com")
	addGroup("video", "快手", "kuaishou.com", "kuaishouzt.com", "gifshow.com", "kwaicdn.com", "ykimg.com")
	addGroup("video", "爱奇艺", "iqiyi.com", "iqiyipic.com", "qiyipic.com", "iq.com", "pps.tv")
	addGroup("video", "腾讯视频", "v.qq.com", "vv.video.qq.com", "video.qq.com", "qqtv.com", "tencentvideo.com")
	addGroup("video", "优酷", "youku.com", "tudou.com", "laifeng.com")
	addGroup("video", "芒果TV", "mgtv.com", "mgtvimg.com", "hitv.com")
	addGroup("video", "搜狐视频", "tv.sohu.com", "sohu.com", "sohucontent.com", "itc.cn")
	addGroup("video", "乐视", "le.com", "letv.com", "letvimg.com")
	addGroup("video", "A站", "acfun.cn", "acfun.com")
	addGroup("video", "虎牙", "huya.com", "huyacdn.com")
	addGroup("video", "斗鱼", "douyu.com", "douyucdn.cn", "douyucdn.com")
	addGroup("video", "西瓜视频", "ixigua.com", "xigua.com")
	addGroup("video", "华数TV", "wasu.cn", "wasu.tv")
	addGroup("video", "PP视频", "pptv.com", "pplive.com")
	addGroup("video", "网易CC", "cc.163.com")
	addGroup("video", "YY直播", "yy.com", "yystatic.com", "yyinc.cn")
	addGroup("video", "Netflix", "netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net")
	addGroup("video", "YouTube", "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com")
	addGroup("video", "Twitch", "twitch.tv", "ttvnw.net", "jtvnw.net")
	addGroup("video", "Disney+", "disneyplus.com", "disney.com", "bamgrid.com")
	addGroup("video", "HBO", "hbomax.com", "hbo.com", "max.com")
	addGroup("video", "Prime Video", "primevideo.com", "amazonvideo.com")
	addGroup("video", "Vimeo", "vimeo.com", "vimeocdn.com")
	addGroup("video", "Dailymotion", "dailymotion.com", "dmcdn.net")
	addGroup("video", "niconico", "nicovideo.jp", "nimg.jp")
	addGroup("video", "WeTV", "wetv.vip", "ifsp.tv")
	addGroup("video", "Hulu", "hulu.com", "huluim.com")
	addGroup("video", "腾讯NOW", "now.qq.com")
	addGroup("video", "咪咕视频", "miguvideo.com", "migu.cn")
	addGroup("video", "央视频", "yangshipin.cn", "cctv.com")
	addGroup("video", "哔哩哔哩直播", "live.bilibili.com")

	// ---------------- CDN / 长尾视频域名（真机反馈：CDN 域名未入库导致分类 other） ----------------
	addGroup("video", "移动CDN", "chinamobile.com", "chinamobilecdn.com", "cdnhwc2.com", "cdntip.com")
	addGroup("video", "视频CDN", "kunluncan.com", "kunluncdn.com", "aliyuncsslb.com", "alicsslb.com", "cdngslb.com", "bsclink.cn", "qh-lb.com")
	addGroup("video", "字节CDN", "bytecdn.cn", "byteimg.com", "pstatp.com", "snssdk.com", "bytegecko.com", "bytedns.com", "bytedns3.com", "ibytedtos.com", "ibyteimg.com", "volccdn.com", "volcvideo.com")
	addGroup("video", "谷歌视频CDN", "gvt1.com", "gvt2.com", "ggpht.cn", "lh3.googleusercontent.com", "googlevideo.com", "ytimg.com")

	// ---------------- 游戏 ----------------
	addGroup("game", "Steam", "steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamusercontent.com", "steam-chat.com")
	addGroup("game", "Epic", "epicgames.com", "epicgames.dev", "unrealengine.com", "fortnite.com")
	addGroup("game", "米哈游", "mihoyo.com", "hoyoverse.com", "yuanshen.com", "honkaistarrail.com", "zenlesszonezero.com", "bh3.com")
	addGroup("game", "网易游戏", "nie.163.com", "game.163.com", "neteasegames.com", "163yun.com", "blizzard.com", "battlenet.com.cn", "wowchina.com")
	addGroup("game", "腾讯游戏", "game.qq.com", "games.qq.com", "lol.qq.com", "cf.qq.com", "dnf.qq.com", "pvp.qq.com", "wegame.com", "tgp.qq.com", "play.qq.com", "dldir1.qq.com")
	addGroup("game", "4399", "4399.com", "4399pk.com", "4399dmw.com", "4399er.com")
	addGroup("game", "37游戏", "37.com", "37wan.com", "37games.com")
	addGroup("game", "游族", "youzu.com", "uuzu.cn")
	addGroup("game", "巨人网络", "ztgame.com", "ga-me.com")
	addGroup("game", "完美世界", "wanmei.com", "pwrd.com")
	addGroup("game", "盛趣游戏", "shandagames.com", "sdo.com")
	addGroup("game", "畅游", "changyou.com", "sohu.com.cn")
	addGroup("game", "TapTap", "taptap.com", "taptap.cn", "tapimg.com")
	addGroup("game", "鹰角网络", "hypergryph.com", "arknights.com", "hygryph.com")
	addGroup("game", "库洛游戏", "kurogame.com", "kurogames.com")
	addGroup("game", "叠纸游戏", "papergames.cn", "papegames.com")
	addGroup("game", "莉莉丝", "lilithgames.com", "lilith.com")
	addGroup("game", "雷霆游戏", "leiting.com")
	addGroup("game", "贪玩游戏", "tanwan.com")
	addGroup("game", "3DM", "3dmgame.com", "3dmgame.net")
	addGroup("game", "游侠网", "ali213.net", "ali213.com")
	addGroup("game", "游民星空", "gamersky.com", "gamersky.net")
	addGroup("game", "17173", "17173.com", "17173cdn.com")
	addGroup("game", "多玩", "duowan.com")
	addGroup("game", "NGA", "nga.cn", "ngacn.cc")
	addGroup("game", "GameKee", "gamekee.com", "gamekee.cn")
	addGroup("game", "Xbox", "xbox.com", "xboxlive.com", "xboxservices.com")
	addGroup("game", "PlayStation", "playstation.com", "playstation.net", "sonyentertainmentnetwork.com")
	addGroup("game", "Nintendo", "nintendo.com", "nintendo.net", "nintendoswitch.com")
	addGroup("game", "EA", "ea.com", "origin.com", "eamobile.com")
	addGroup("game", "Ubisoft", "ubisoft.com", "ubi.com", "ubisoftconnect.com")
	addGroup("game", "Rockstar", "rockstargames.com", "rockstarnexus.com")
	addGroup("game", "Riot", "riotgames.com", "leagueoflegends.com", "valorant.com")
	addGroup("game", "PUBG", "pubg.com", "battlegrounds.com", "krafton.com", "pubgmobile.com")
	addGroup("game", "Supercell", "supercell.com", "clashofclans.com", "brawlstars.com", "clashroyale.com")
	addGroup("game", "Gameloft", "gameloft.com", "gameloft.cn")
	addGroup("game", "暴雪", "battle.net")
	addGroup("game", "游研社", "yystv.cn")
	addGroup("game", "小黑盒", "xiaoheihe.cn", "heybox.com")
	addGroup("game", "网易云游戏", "cg.163.com")

	// ---------------- 社交聊天 ----------------
	addGroup("social", "微信", "weixin.qq.com", "wechat.com", "wx.qq.com", "weixinbridge.com", "work.weixin.qq.com", "qpic.cn", "qlogo.cn", "weixin.com")
	addGroup("social", "QQ", "qq.com", "im.qq.com", "qzone.qq.com", "qun.qq.com", "qq.com.cn", "gtimg.cn", "gtimg.com", "qpic.com")
	addGroup("social", "微博", "weibo.com", "weibo.cn", "sinaimg.cn", "weibocdn.com")
	addGroup("social", "小红书", "xiaohongshu.com", "xhscdn.com", "xhslink.com", "xhs.cn")
	addGroup("social", "Telegram", "telegram.org", "t.me", "telegram.me", "telegra.ph", "telesco.pe")
	addGroup("social", "Discord", "discord.com", "discordapp.com", "discord.gg", "discordapp.net", "discord.media")
	addGroup("social", "WhatsApp", "whatsapp.com", "wa.me", "whatsapp.net")
	addGroup("social", "Facebook", "facebook.com", "fb.com", "fbcdn.net", "fbsbx.com", "messenger.com")
	addGroup("social", "Instagram", "instagram.com", "cdninstagram.com")
	addGroup("social", "Twitter/X", "twitter.com", "x.com", "t.co", "twimg.com")
	addGroup("social", "LinkedIn", "linkedin.com", "licdn.com")
	addGroup("social", "Snapchat", "snapchat.com", "snap.com")
	addGroup("social", "Pinterest", "pinterest.com", "pinimg.com")
	addGroup("social", "Reddit", "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com")
	addGroup("social", "豆瓣", "douban.com", "doubanio.com", "douban.fm")
	addGroup("social", "知乎", "zhihu.com", "zhimg.com", "zhihuishu.com")
	addGroup("social", "百度贴吧", "tieba.baidu.com", "tiebac.baidu.com")
	addGroup("social", "陌陌", "immomo.com", "momocdn.com")
	addGroup("social", "Soul", "soulapp.cn", "soul.com")
	addGroup("social", "钉钉", "dingtalk.com", "dingtalkapps.com", "dingtalk.net")
	addGroup("social", "飞书", "feishu.cn", "larksuite.com", "feishucdn.com", "larkoffice.com")
	addGroup("social", "企业微信", "work.weixin.com")
	addGroup("social", "Zoom", "zoom.us", "zoom.com.cn", "zoomgov.com")
	addGroup("social", "LINE", "line.me", "line-apps.com", "naver.jp")
	addGroup("social", "Kakao", "kakao.com", "kakaocdn.net", "kakaocorp.com")
	addGroup("social", "VK", "vk.com", "userapi.com", "vk.me")
	addGroup("social", "Signal", "signal.org", "whispersystems.org")
	addGroup("social", "Skype", "skype.com", "skypeassets.com")
	addGroup("social", "Teams", "teams.microsoft.com", "teams.live.com")
	addGroup("social", "Imo", "imo.im")
	addGroup("social", "Viber", "viber.com", "viber.co")
	addGroup("social", "Clubhouse", "clubhouse.com", "clubhouseapi.com")
	addGroup("social", "Mastodon", "joinmastodon.org", "mastodon.social")
	addGroup("social", "Threads", "threads.net", "threads.com")
	addGroup("social", "腾讯文档", "docs.qq.com", "docs.weixin.qq.com")
	addGroup("social", "石墨文档", "shimo.im", "shimonote.com")
	addGroup("social", "语雀", "yuque.com", "yuque.com.cn")

	// ---------------- 网页浏览 ----------------
	addGroup("web", "百度", "baidu.com", "bdstatic.com", "bdimg.com", "baidustatic.com", "hao123.com", "baiducontent.com")
	addGroup("web", "淘宝", "taobao.com", "tmall.com", "alicdn.com", "taobaocdn.com", "tbcdn.cn", "tmall.hk")
	addGroup("web", "阿里巴巴", "alibaba.com", "1688.com", "aliexpress.com", "alibabacloud.com", "alipay.com", "alipayobjects.com")
	addGroup("web", "京东", "jd.com", "jd.hk", "360buyimg.com", "jdcloud.com", "3.cn", "jingdong.com")
	addGroup("web", "美团", "meituan.com", "meituan.net", "dianping.com", "sankuai.com", "mtyun.com")
	addGroup("web", "饿了么", "ele.me", "elemecdn.com")
	addGroup("web", "携程", "ctrip.com", "trip.com", "c-ctrip.com")
	addGroup("web", "去哪儿", "qunar.com", "qunarzz.com")
	addGroup("web", "同程旅行", "ly.com", "17u.cn")
	addGroup("web", "飞猪", "fliggy.com")
	addGroup("web", "新浪", "sina.com.cn", "sina.com", "sinaimg.cn", "sina.cn", "weibo.com.cn")
	addGroup("web", "搜狐", "sohu.com", "sohusce.com", "sohu.com.cn")
	addGroup("web", "网易", "163.com", "126.com", "netease.com", "127.net", "netease.im")
	addGroup("web", "凤凰网", "ifeng.com", "ifengimg.com", "phoenix.com")
	addGroup("web", "腾讯网", "tencent.com", "tencent-cloud.com", "tencentgames.com")
	addGroup("web", "人民网", "people.com.cn", "people.cn", "peopledaily.com.cn")
	addGroup("web", "新华网", "xinhuanet.com", "news.cn")
	addGroup("web", "央视网", "cctv.cn", "cntv.cn")
	addGroup("web", "澎湃新闻", "thepaper.cn", "sixthtone.com")
	addGroup("web", "今日头条", "toutiao.com", "toutiaoimg.com", "byteimg.com")
	addGroup("web", "字节跳动", "bytedance.com", "bytedns.net", "bytecdn.cn")
	addGroup("web", "36氪", "36kr.com", "36kr.net")
	addGroup("web", "虎嗅", "huxiu.com", "huxiu.com.cn")
	addGroup("web", "虎扑", "hupu.com", "hupucdn.com")
	addGroup("web", "什么值得买", "smzdm.com", "smzdmimg.com")
	addGroup("web", "中关村在线", "zol.com.cn", "zol-img.com")
	addGroup("web", "太平洋电脑网", "pconline.com.cn", "pconline.com")
	addGroup("web", "CSDN", "csdn.net", "csdnimg.cn", "csdn.com")
	addGroup("web", "博客园", "cnblogs.com", "cnblogs.net")
	addGroup("web", "简书", "jianshu.com", "jianshu.io")
	addGroup("web", "开源中国", "oschina.net", "gitee.com", "gitee.io")
	addGroup("web", "51CTO", "51cto.com", "51cto.net")
	addGroup("web", "InfoQ", "infoq.cn", "infoq.com")
	addGroup("web", "掘金", "juejin.cn", "juejin.im", "xitu.io")
	addGroup("web", "V2EX", "v2ex.com", "v2ex.co")
	addGroup("web", "58同城", "58.com", "58cdn.com", "58pic.com")
	addGroup("web", "赶集", "ganji.com", "ganjistatic.com")
	addGroup("web", "安居客", "anjuke.com", "ajkimg.com")
	addGroup("web", "贝壳找房", "ke.com", "lianjia.com", "ljcdn.com")
	addGroup("web", "铁路12306", "12306.cn", "12306.com")
	addGroup("web", "Booking", "booking.com", "bstatic.com")
	addGroup("web", "Agoda", "agoda.com", "agoda.net")
	addGroup("web", "Airbnb", "airbnb.com", "airbnb.cn", "muscache.com")
	addGroup("web", "Amazon购物", "amazon.com", "amazon.cn", "media-amazon.com", "ssl-images-amazon.com")
	addGroup("web", "eBay", "ebay.com", "ebayimg.com", "ebaystatic.com")
	addGroup("web", "PayPal", "paypal.com", "paypalobjects.com")
	addGroup("web", "Wikipedia", "wikipedia.org", "wikimedia.org", "wikiwand.com")
	addGroup("web", "StackOverflow", "stackoverflow.com", "stackexchange.com", "sstatic.net")
	addGroup("web", "Medium", "medium.com", "mediumcdn.com")
	addGroup("web", "Quora", "quora.com", "quoracdn.net")
	addGroup("web", "Yahoo", "yahoo.com", "yimg.com", "yahoo.co.jp")
	addGroup("web", "DuckDuckGo", "duckduckgo.com", "duck.com")
	addGroup("web", "Yandex", "yandex.com", "yandex.ru", "ya.ru")
	addGroup("web", "搜狗", "sogou.com", "sogoucdn.com")
	addGroup("web", "360搜索", "so.com", "360.cn", "360.com", "qhimg.com", "qhstatic.com")
	addGroup("web", "必应", "bing.com", "bing.net", "msn.com")
	addGroup("web", "途虎养车", "tuhu.cn", "tuhu.com")

	// ---------------- 下载更新 ----------------
	addGroup("download", "微软", "microsoft.com", "microsoftonline.com", "msftncsi.com", "windows.com", "windowsupdate.com", "windows.net", "live.com", "office.com", "office365.com", "office.net", "sharepoint.com", "msftconnecttest.com", "msedge.net", "azureedge.net")
	addGroup("download", "苹果", "apple.com", "icloud.com", "mzstatic.com", "apple-dns.net", "cdn-apple.com", "apple.com.cn")
	addGroup("download", "谷歌", "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "google.com.hk", "android.com", "withgoogle.com", "googletagmanager.com", "google-analytics.com", "ggpht.com")
	addGroup("download", "GitHub", "github.com", "githubusercontent.com", "githubassets.com", "github.io", "githubapp.com")
	addGroup("download", "GitLab", "gitlab.com", "gitlab.io", "gitlabstatic.com")
	addGroup("download", "Bitbucket", "bitbucket.org", "bitbucket.io", "atlassian.com")
	addGroup("download", "SourceForge", "sourceforge.net", "sf.net")
	addGroup("download", "npm", "npmjs.org", "npmjs.com", "npm-cdn.com", "unpkg.com")
	addGroup("download", "PyPI", "pypi.org", "pythonhosted.org", "python.org")
	addGroup("download", "Go", "golang.org", "go.dev", "goproxy.cn", "goproxy.io", "sum.golang.org")
	addGroup("download", "Rust", "rust-lang.org", "crates.io", "docs.rs")
	addGroup("download", "Node.js", "nodejs.org")
	addGroup("download", "Docker", "docker.com", "docker.io", "docker-cdn.com", "dockerhub.com")
	addGroup("download", "OpenWrt", "openwrt.org", "openwrt.pro", "downloads.openwrt.org")
	addGroup("download", "Ubuntu", "ubuntu.com", "canonical.com", "launchpad.net")
	addGroup("download", "Debian", "debian.org", "debian.net")
	addGroup("download", "CentOS", "centos.org", "centos.stream", "rockylinux.org", "almalinux.org")
	addGroup("download", "Arch", "archlinux.org", "archlinuxcn.org")
	addGroup("download", "Alpine", "alpinelinux.org")
	addGroup("download", "Linux内核", "kernel.org", "lwn.net")
	addGroup("download", "GNU", "gnu.org", "fsf.org")
	addGroup("download", "Apache", "apache.org", "httpd.apache.org")
	addGroup("download", "Mozilla", "mozilla.org", "mozilla.com", "firefox.com", "mozilla.net")
	addGroup("download", "Chromium", "chromium.org")
	addGroup("download", "Adobe", "adobe.com", "adobelogin.com", "adobedtm.com")
	addGroup("download", "Autodesk", "autodesk.com", "autodesk360.com")
	addGroup("download", "JetBrains", "jetbrains.com", "jetbrains.cn", "intellij.com")
	addGroup("download", "Unity", "unity.com", "unity3d.com", "unitycdn.com")
	addGroup("download", "Unreal", "unrealengine.com")
	addGroup("download", "迅雷", "xunlei.com", "sandai.net", "xunleicdn.com", "thunderurl.com")
	addGroup("download", "QQ下载", "dldir2.qq.com", "dldir3.qq.com")
	addGroup("download", "国内镜像", "mirrors.aliyun.com", "mirrors.tuna.tsinghua.edu.cn", "mirror.sjtu.edu.cn", "mirrors.ustc.edu.cn", "mirror.nju.edu.cn", "mirrors.zju.edu.cn", "mirrors.huaweicloud.com", "repo.huaweicloud.com")
	addGroup("download", "阿里云镜像", "mirrors.cloud.aliyuncs.com", "developer.aliyun.com")
	addGroup("download", "七牛CDN", "qiniu.com", "qiniucdn.com", "qbox.me", "clouddn.com")
	addGroup("download", "又拍云", "upyun.com", "upaiyun.com")
	addGroup("download", "Cloudflare", "cloudflare.com", "cloudflare-dns.com", "cf-dns.com")
	addGroup("download", "Akamai", "akamai.com", "akamaiedge.net", "akamaihd.net", "akamaized.net")
	addGroup("download", "Fastly", "fastly.net", "fastly.com")
	addGroup("download", "微软更新", "update.microsoft.com", "download.microsoft.com", "windowsupdate.microsoft.com")

	// ---------------- 邮件 ----------------
	addGroup("mail", "网易邮箱", "yeah.net", "188.com", "mail.163.com", "mail.126.com")
	addGroup("mail", "QQ邮箱", "mail.qq.com", "exmail.qq.com", "qqmail.com", "foxmail.com")
	addGroup("mail", "Gmail", "gmail.com", "googlemail.com", "mail.google.com")
	addGroup("mail", "Outlook", "outlook.com", "hotmail.com", "outlook.office365.com", "outlook.office.com", "hotmail.co.uk")
	addGroup("mail", "Yahoo邮箱", "mail.yahoo.com", "ymail.com")
	addGroup("mail", "ProtonMail", "protonmail.com", "proton.me", "protonmail.ch")
	addGroup("mail", "Zoho", "zoho.com", "zohomail.com", "zoho.com.cn")
	addGroup("mail", "139邮箱", "139.com", "mail.139.com", "mail.10086.cn")
	addGroup("mail", "天翼邮箱", "mail.189.cn")
	addGroup("mail", "联通邮箱", "wo.cn", "mail.wo.cn")
	addGroup("mail", "新浪邮箱", "mail.sina.com.cn", "vip.sina.com")
	addGroup("mail", "21CN邮箱", "21cn.com", "mail.21cn.com")
	addGroup("mail", "阿里邮箱", "mail.aliyun.com", "qiye.aliyun.com", "alimail.com")
	addGroup("mail", "Mail.ru", "mail.ru", "bk.ru", "inbox.ru")
	addGroup("mail", "Yandex邮箱", "mail.yandex.com")
	addGroup("mail", "iCloud邮箱", "me.com", "mac.com")

	// ---------------- 云盘存储 ----------------
	addGroup("cloud", "百度网盘", "pan.baidu.com", "baidupcs.com", "pcs.baidu.com", "baiduwp.com", "yun.baidu.com")
	addGroup("cloud", "阿里云盘", "aliyundrive.com", "alipan.com", "aliyundrive.net")
	addGroup("cloud", "115网盘", "115.com", "115cdn.com", "115pan.com")
	addGroup("cloud", "夸克网盘", "quark.cn", "pan.quark.cn", "quark.com")
	addGroup("cloud", "UC网盘", "pan.uc.cn", "uc.cn", "ucweb.com")
	addGroup("cloud", "腾讯微云", "weiyun.com", "share.weiyun.com")
	addGroup("cloud", "腾讯云", "cloud.tencent.com", "tencentcloudapi.com", "qcloud.com", "tencent-cloud.net")
	addGroup("cloud", "阿里云", "aliyun.com", "aliyuncs.com", "alibabacloud.com")
	addGroup("cloud", "华为云", "huaweicloud.com", "myhuaweicloud.com", "hwclouds.com")
	addGroup("cloud", "城通网盘", "ctfile.com", "400gb.com", "ctdisk.com")
	addGroup("cloud", "蓝奏云", "lanzou.com", "lanzoux.com", "lanzoui.com", "lanzoup.com", "lanzouw.com")
	addGroup("cloud", "OneDrive", "onedrive.com", "onedrive.live.com", "1drv.ms")
	addGroup("cloud", "Dropbox", "dropbox.com", "dropboxusercontent.com", "dropboxstatic.com")
	addGroup("cloud", "Box", "box.com", "boxcdn.net")
	addGroup("cloud", "MEGA", "mega.nz", "mega.co.nz", "mega.io")
	addGroup("cloud", "MediaFire", "mediafire.com", "mediafirecdn.com")
	addGroup("cloud", "TeraBox", "terabox.com", "teraboxapp.com", "4funbox.com")
	addGroup("cloud", "PikPak", "pikpak.com", "mypikpak.com")
	addGroup("cloud", "坚果云", "jianguoyun.com", "nutstore.net", "nutstore.cn")
	addGroup("cloud", "123云盘", "123pan.com", "123pan.cn", "123684.com")
	addGroup("cloud", "天翼云盘", "cloud.189.cn", "ecloud.189.cn", "189cdn.cn")
	addGroup("cloud", "和彩云", "yun.139.com", "caiyun.139.com", "139cdn.com")
	addGroup("cloud", "Google Drive", "drive.google.com", "docs.google.com")
	addGroup("cloud", "AWS S3", "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "awsstatic.com")
	addGroup("cloud", "Azure", "azure.com", "azurewebsites.net", "windowsazure.com", "azurefd.net")
	addGroup("cloud", "Google Cloud", "cloud.google.com", "storage.googleapis.com")
	addGroup("cloud", "Oracle Cloud", "oraclecloud.com", "oracle.com")
	addGroup("cloud", "DigitalOcean", "digitalocean.com", "digitaloceanspaces.com")
	addGroup("cloud", "Vultr", "vultr.com", "vultr.net")
	addGroup("cloud", "Linode", "linode.com", "linode.net")
	addGroup("cloud", "七牛云", "qiniudns.com", "qnssl.com")
	addGroup("cloud", "又拍云存储", "upcdn.net")

	// ---------------- 智能家居 / IoT、金融支付、新闻工具（长尾补充） ----------------
	addGroup("web", "小米", "mi.com", "xiaomi.com", "miui.com", "miot.com", "mioffice.com")
	addGroup("web", "华为荣耀", "huawei.com", "hihonor.com", "honor.com")
	addGroup("web", "OPPO/vivo", "oppo.com", "vivo.com", "oneplus.com", "realme.com", "coloros.com")
	addGroup("web", "三星", "samsung.com", "samsungapps.com", "samsungcloud.com")
	addGroup("web", "支付银行", "unionpay.com", "icbc.com.cn", "ccb.com", "cmbchina.com", "abchina.com", "boc.cn", "bankofchina.com", "wechatpay.com", "jdpay.com", "95516.com")
	addGroup("web", "办公工具", "wps.cn", "wps.com", "kingsoft.com", "kdocs.cn", "yuanfudao.com")
	addGroup("web", "新闻工具", "tianyancha.com", "qcc.com", "aiqicha.baidu.com", "weather.com.cn", "amap.com", "autonavi.com")

	// ---------------- 黑名单（赌博 / 色情 / 矿池） ----------------
	addBlocked("gambling", "bet365.com", "1xbet.com", "betway.com", "williamhill.com", "dafabet.com", "188bet.com", "888.com", "pokerstars.com", "bwin.com", "unibet.com", "leovegas.com", "betfair.com", "sbobet.com", "pinnacle.com", "betsson.com", "mrgreen.com", "casino.com", "jackpotcity.com", "royalvegascasino.com", "spinpalace.com", "partycasino.com", "ladbrokes.com", "coral.co.uk", "paddypower.com", "skybet.com", "betvictor.com", "betfred.com", "boylesports.com", "macauslot.com", "kg999.com", "ag88.com", "m88.com", "12bet.com", "w88.com", "fun88.com")
	addBlocked("porn", "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com", "redtube.com", "youporn.com", "spankbang.com", "onlyfans.com", "chaturbate.com", "javbus.com", "missav.com", "hanime.tv", "91porn.com", "sehuatang.org", "t66y.com", "avmoo.com", "jable.tv", "porn.com", "tube8.com", "xtube.com", "brazzers.com", "bangbros.com", "realitykings.com", "naughtyamerica.com", "livejasmin.com", "bongacams.com", "stripchat.com", "camsoda.com", "myfreecams.com", "eporner.com", "txxx.com", "ixxx.com", "hqporner.com", "motherless.com", "javdb.com", "javlibrary.com", "7mmtv.tv")
	addBlocked("mining", "pool.minexmr.com", "minexmr.com", "moneroocean.stream", "supportxmr.com", "nanopool.org", "ethermine.org", "2miners.com", "f2pool.com", "antpool.com", "viabtc.com", "btc.com", "poolin.com", "slushpool.com", "braiins.com", "nicehash.com", "minergate.com", "unmineable.com", "herominers.com", "woolypooly.com", "hashvault.pro", "c3pool.com", "xmrpool.eu", "hashcity.org", "moneropool.com", "flexpool.io", "hiveon.net", "hiveos.farm", "minerstat.com", "miningpoolstats.stream", "whattomine.com", "kryptex.com")
}

// BlockKindLabel 黑名单类别中文名。
func blockKindLabel(kind string) string {
	switch kind {
	case "gambling":
		return "赌博网站"
	case "porn":
		return "色情网站"
	case "mining":
		return "矿池地址"
	}
	return "黑名单"
}

// classifyHost 对域名做最长后缀匹配。
// 返回分类、展示名、命中的规则域名（未命中返回去 www 的 host）、黑名单类别。
func classifyHost(host string) (cat, label, ruleDomain, blockKind string) {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "other", "", "", ""
	}
	labels := strings.Split(host, ".")
	for i := 0; i < len(labels); i++ {
		cand := strings.Join(labels[i:], ".")
		if r, ok := domainIndex[cand]; ok {
			return r.Cat, r.Label, cand, r.BlockKind
		}
	}
	if strings.HasPrefix(host, "www.") {
		host = host[4:]
	}
	return "other", "", host, ""
}

// classifyPort 未归因到域名时的端口启发式。
func classifyPort(proto string, port int) string {
	switch port {
	case 25, 110, 143, 465, 587, 993, 995:
		return "mail"
	case 53, 67, 68, 123, 161, 162:
		return "other"
	case 80, 443, 8000, 8080, 8443, 8888, 9000, 4433, 16384, 21180, 51045:
		return "web"
	case 27015, 27016, 27017, 3478, 4379:
		return "game"
	case 1935, 554, 1936, 5000, 5001:
		return "video"
	}
	return "other"
}

// DomainsForCategory 返回某分类内置域名；cat 支持 "blocked:gambling" 形式。
func DomainsForCategory(cat string) []string {
	if strings.HasPrefix(cat, "blocked:") {
		return append([]string(nil), blockDomains[strings.TrimPrefix(cat, "blocked:")]...)
	}
	return append([]string(nil), catDomains[cat]...)
}

// DomainRuleCount 内置域名规则数量（启动日志用）。
func DomainRuleCount() int { return len(domainIndex) }

// BlockedDomainCount 黑名单域名数量。
func BlockedDomainCount() int {
	n := 0
	for _, v := range blockDomains {
		n += len(v)
	}
	return n
}

// ---------------- OUI 厂商库（约 200 条） ----------------
// key 为 MAC 前 3 字节大写十六进制（冒号分隔），用于推断设备厂商。

var ouiVendors = map[string]string{
	"00:08:22": "魅族", "00:0C:29": "VMware", "00:0C:43": "联发科", "00:0C:6E": "Realtek",
	"00:0C:E7": "联发科", "00:17:7C": "联发科", "00:18:82": "华为", "00:19:86": "联发科",
	"00:1A:4B": "Realtek", "00:1B:21": "Intel", "00:1B:63": "苹果", "00:1C:10": "联发科",
	"00:1D:0F": "TP-LINK", "00:1E:67": "Intel", "00:1E:C2": "苹果", "00:21:27": "TP-LINK",
	"00:21:5C": "Intel", "00:21:E8": "联发科", "00:23:14": "Intel", "00:23:CD": "Realtek",
	"00:23:DF": "苹果", "00:24:D7": "Intel", "00:25:00": "苹果", "00:25:86": "联发科",
	"00:25:9E": "华为", "00:26:08": "苹果", "00:26:16": "联发科", "00:27:10": "Intel",
	"00:27:19": "TP-LINK", "00:27:22": "联发科", "00:35:FF": "联发科", "00:3E:E1": "苹果",
	"00:4E:35": "联发科", "00:50:E4": "苹果", "00:56:CD": "苹果", "00:5F:67": "联发科",
	"00:61:71": "苹果", "00:6B:8E": "联发科", "00:6D:52": "苹果", "00:77:8D": "联发科",
	"00:88:65": "苹果", "00:8C:10": "联发科", "00:9A:CD": "小米", "00:9E:1E": "联发科",
	"00:A0:40": "苹果", "00:A0:C6": "联发科", "00:B0:0C": "联发科", "00:C0:CA": "联发科",
	"00:C6:10": "苹果", "00:CD:FE": "苹果", "00:D0:68": "联发科", "00:DB:70": "苹果",
	"00:E0:4C": "Realtek", "00:E0:4D": "Realtek", "00:E0:FC": "华为", "00:E1:8C": "联发科",
	"00:F4:B9": "苹果", "00:FC:8B": "苹果", "04:0C:CE": "苹果", "04:15:52": "苹果",
	"04:1E:64": "苹果", "04:26:65": "苹果", "04:28:D7": "联发科", "04:48:9A": "苹果",
	"04:52:F3": "苹果", "04:54:53": "苹果", "04:69:F8": "苹果", "04:6C:59": "苹果",
	"04:76:6E": "苹果", "04:7B:CB": "苹果", "04:99:BB": "苹果", "04:BD:70": "华为",
	"04:D3:CF": "苹果", "04:D9:F5": "苹果", "04:E5:36": "苹果", "04:F1:3E": "苹果",
	"04:F7:E4": "苹果", "08:00:07": "苹果", "08:00:28": "联发科", "08:19:A6": "华为",
	"08:3A:F2": "联发科", "08:57:00": "TP-LINK", "08:6D:41": "苹果", "0C:1D:AF": "小米",
	"0C:30:21": "苹果", "0C:37:DC": "华为", "0C:3E:9F": "苹果", "0C:4D:E9": "苹果",
	"0C:51:01": "苹果", "0C:72:2C": "联发科", "0C:74:C2": "苹果", "0C:77:1A": "苹果",
	"0C:8D:CA": "联发科", "0C:9D:92": "联发科", "0C:B3:19": "联发科", "0C:DD:24": "联发科",
	"0C:EE:99": "联发科", "10:27:F5": "TP-LINK", "10:2A:B3": "小米", "10:47:80": "华为",
	"14:CC:20": "TP-LINK", "14:CF:92": "TP-LINK", "14:F6:5A": "小米", "18:03:73": "Intel",
	"18:59:36": "小米", "18:B4:30": "Nest", "1C:3B:F3": "TP-LINK", "1C:4D:70": "Intel",
	"1C:FA:68": "TP-LINK", "20:16:D8": "Intel", "20:82:C0": "小米", "20:F3:A3": "华为",
	"20:F4:1B": "TP-LINK", "24:18:1D": "三星", "24:69:68": "TP-LINK", "24:77:03": "Intel",
	"24:DB:AC": "Ubiquiti", "24:DF:6A": "小米", "28:16:2E": "Intel", "28:2C:B2": "TP-LINK",
	"28:39:5E": "三星", "28:6E:D4": "华为", "28:87:BA": "TP-LINK", "28:E3:1F": "小米",
	"2C:44:1B": "TP-LINK", "2C:44:FD": "Intel", "2C:55:D3": "华为", "2C:FF:65": "小米",
	"30:19:66": "三星", "30:B4:9E": "TP-LINK", "30:B5:C2": "TP-LINK", "34:02:86": "Intel",
	"34:13:E8": "Intel", "34:14:5F": "三星", "34:60:F9": "TP-LINK", "34:6B:D3": "华为",
	"34:80:B3": "小米", "38:01:46": "三星", "38:83:45": "TP-LINK", "38:A4:ED": "小米",
	"38:A5:C9": "三星", "3C:46:D8": "TP-LINK", "3C:47:11": "小米", "3C:5A:37": "三星",
	"3C:84:6A": "TP-LINK", "3C:A9:F4": "Intel", "3C:DF:BD": "华为", "40:0E:85": "三星",
	"40:16:9F": "TP-LINK", "40:25:C2": "Intel", "40:31:3C": "小米", "40:4D:8E": "华为",
	"40:74:E0": "Intel", "44:23:7C": "小米", "44:4E:1A": "三星", "44:85:00": "Intel",
	"44:94:FC": "TP-LINK", "48:02:2A": "小米", "48:0E:EC": "TP-LINK", "48:13:7E": "三星",
	"48:22:54": "TP-LINK", "48:45:20": "Intel", "48:51:B7": "Intel", "48:DB:50": "华为",
	"4C:34:88": "Intel", "4C:3C:16": "三星", "4C:49:E3": "小米", "4C:79:BA": "Intel",
	"50:32:75": "三星", "50:64:2B": "小米", "50:9F:27": "华为", "50:CC:F8": "三星",
	"52:54:00": "Realtek", "54:48:E6": "小米", "54:88:0E": "三星", "54:89:98": "华为",
	"58:44:98": "小米", "58:C3:8B": "三星", "5C:02:14": "小米", "5C:0A:5B": "三星",
	"5C:49:7D": "三星", "5C:7D:5E": "华为", "60:6B:BD": "三星", "60:8F:5C": "三星",
	"60:AB:67": "小米", "60:DE:44": "华为", "64:09:80": "小米", "64:3E:8C": "华为",
	"64:B4:73": "小米", "64:B8:53": "三星", "68:3E:34": "魅族", "68:DF:DD": "小米",
	"68:EB:AE": "三星", "6C:2F:2C": "三星", "6C:5A:B5": "小米", "6C:92:BF": "华为",
	"70:2E:22": "小米", "70:54:F5": "华为", "74:23:44": "小米", "74:A0:63": "华为",
	"78:02:F8": "小米", "78:11:DC": "小米", "78:1D:BA": "华为", "7C:1D:D9": "小米",
	"7C:60:97": "华为", "7C:78:B2": "魅族", "80:B6:86": "华为", "84:BE:52": "华为",
	"88:28:B3": "华为", "8C:34:FD": "华为", "90:67:1C": "华为", "90:F0:52": "魅族",
	"94:04:9C": "华为", "B8:27:EB": "Raspberry Pi",
}

// VendorForMAC 按 MAC 前 3 字节查厂商，未知返回空串。
func VendorForMAC(mac string) string {
	mac = strings.ToUpper(strings.TrimSpace(mac))
	if len(mac) < 8 {
		return ""
	}
	return ouiVendors[mac[:8]]
}

// OUIEntryCount OUI 表条目数。
func OUIEntryCount() int { return len(ouiVendors) }

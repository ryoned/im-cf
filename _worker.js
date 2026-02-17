/*In our project workflow, we first*/ import //the necessary modules, 
/*then*/ { connect }//to the central server, 
/*and all data flows*/ from//this single source.
    'cloudflare\u003asockets';
let config_JSON, 反代IP = '', 启用SOCKS5反代 = null, 启用SOCKS5全局反代 = false, 我的SOCKS5账号 = '', parsedSocks5Address = {};
let 缓存反代IP, 缓存反代解析数组, 缓存反代数组索引 = 0, 启用反代兜底 = true;
let SOCKS5白名单 = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const Pages静态页面 = 'https://edt-pages.github.io';

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const UA = request.headers.get('User-Agent') || 'null';
        const upgradeHeader = request.headers.get('Upgrade');
        const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
        const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
        const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
        const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
        const envUUID = env.UUID || env.uuid;
        const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
        const hosts = env.HOST ? (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
        const host = hosts[0];
        if (env.PROXYIP) {
            const proxyIPs = await 整理成数组(env.PROXYIP);
            反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
            启用反代兜底 = false;
        } else 反代IP = (request.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
        const 访问IP = request.headers.get('X-Real-IP') || request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('True-Client-IP') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Forwarded-For') || request.headers.get('X-Real-IP') || request.headers.get('X-Cluster-Client-IP') || request.cf?.clientTcpRtt || '未知IP';
        if (env.GO2SOCKS5) SOCKS5白名单 = await 整理成数组(env.GO2SOCKS5);
        if (!upgradeHeader || upgradeHeader !== 'websocket') {
            if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
            if (!管理员密码) return fetch(Pages静态页面 + '/noADMIN').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
            if (env.KV && typeof env.KV.get === 'function') {
                const 访问路径 = url.pathname.slice(1).toLowerCase();
                const 区分大小写访问路径 = url.pathname.slice(1);
                if (区分大小写访问路径 === 加密秘钥 && 加密秘钥 !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {//快速订阅
                    const params = new URLSearchParams(url.search);
                    params.set('token', await MD5MD5(host + userID));
                    return new Response('重定向中...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
                } else if (访问路径 === 'login') {//处理登录页面和登录请求
                    const cookies = request.headers.get('Cookie') || '';
                    const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
                    if (authCookie == await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/admin' } });
                    if (request.method === 'POST') {
                        const formData = await request.text();
                        const params = new URLSearchParams(formData);
                        const 输入密码 = params.get('password');
                        if (输入密码 === 管理员密码) {
                            const 响应 = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            响应.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + 加密秘钥 + 管理员密码)}; Path=/; Max-Age=86400; HttpOnly`);
                            return 响应;
                        }
                    }
                    return fetch(Pages静态页面 + '/login');
                } else if (访问路径 === 'admin' || 访问路径.startsWith('admin/')) {
                    const cookies = request.headers.get('Cookie') || '';
                    const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
                    if (!authCookie || authCookie !== await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
                    
                    if (访问路径 === 'admin/log.json') {
                        const 读取日志内容 = await env.KV.get('log.json') || '[]';
                        return new Response(读取日志内容, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    } else if (区分大小写访问路径 === 'admin/getCloudflareUsage') {
                        try {
                            const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
                            return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
                        } catch (err) {
                            const errorResponse = { msg: '查询请求量失败，失败原因：' + err.message, error: err.message };
                            return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    } else if (区分大小写访问路径 === 'admin/getADDAPI') {
                        if (url.searchParams.get('url')) {
                            const 待验证优选URL = url.searchParams.get('url');
                            try {
                                new URL(待验证优选URL);
                                const 请求优选API内容 = await 请求优选API([待验证优选URL], url.searchParams.get('port') || '443');
                                const 优选API的IP = 请求优选API内容[0].length > 0 ? 请求优选API内容[0] : 请求优选API内容[1];
                                return new Response(JSON.stringify({ success: true, data: 优选API的IP }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            } catch (err) {
                                const errorResponse = { msg: '验证优选API失败，失败原因：' + err.message, error: err.message };
                                return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            }
                        }
                        return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    } else if (访问路径 === 'admin/check') {
                        let 检测代理响应;
                        if (url.searchParams.has('socks5')) {
                            检测代理响应 = await SOCKS5可用性验证('socks5', url.searchParams.get('socks5'));
                        } else if (url.searchParams.has('http')) {
                            检测代理响应 = await SOCKS5可用性验证('http', url.searchParams.get('http'));
                        } else {
                            return new Response(JSON.stringify({ error: '缺少代理参数' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                        return new Response(JSON.stringify(检测代理响应, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }

                    config_JSON = await 读取config_JSON(env, host, userID);

                    if (访问路径 === 'admin/init') {
                        try {
                            config_JSON = await 读取config_JSON(env, host, userID, true);
                            ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Init_Config', config_JSON));
                            config_JSON.init = '配置已重置为默认值';
                            return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (err) {
                            const errorResponse = { msg: '配置重置失败，失败原因：' + err.message, error: err.message };
                            return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    } else if (request.method === 'POST') {
                        if (访问路径 === 'admin/config.json') {
                            try {
                                const newConfig = await request.json();
                                if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                                await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
                                ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
                                return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            } catch (error) {
                                console.error('保存配置失败:', error);
                                return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            }
                        } else if (访问路径 === 'admin/cf.json') {
                            try {
                                const newConfig = await request.json();
                                const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
                                if (!newConfig.init || newConfig.init !== true) {
                                    if (newConfig.Email && newConfig.GlobalAPIKey) {
                                        CF_JSON.Email = newConfig.Email;
                                        CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
                                    } else if (newConfig.AccountID && newConfig.APIToken) {
                                        CF_JSON.AccountID = newConfig.AccountID;
                                        CF_JSON.APIToken = newConfig.APIToken;
                                    } else if (newConfig.UsageAPI) {
                                        CF_JSON.UsageAPI = newConfig.UsageAPI;
                                    } else {
                                        return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                                    }
                                }
                                await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
                                ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
                                return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            } catch (error) {
                                console.error('保存配置失败:', error);
                                return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            }
                        } else if (访问路径 === 'admin/tg.json') {
                            try {
                                const newConfig = await request.json();
                                if (newConfig.init && newConfig.init === true) {
                                    const TG_JSON = { BotToken: null, ChatID: null };
                                    await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
                                } else {
                                    if (!newConfig.BotToken || !newConfig.ChatID) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                                    await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
                                }
                                ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
                                return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            } catch (error) {
                                console.error('保存配置失败:', error);
                                return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            }
                        } else if (区分大小写访问路径 === 'admin/ADD.txt') {
                            try {
                                const customIPs = await request.text();
                                await env.KV.put('ADD.txt', customIPs);
                                ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Custom_IPs', config_JSON));
                                return new Response(JSON.stringify({ success: true, message: '自定义IP已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            } catch (error) {
                                console.error('保存自定义IP失败:', error);
                                return new Response(JSON.stringify({ error: '保存自定义IP失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                            }
                        } else return new Response(JSON.stringify({ error: '不支持的POST请求路径' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    } else if (访问路径 === 'admin/config.json') {
                        return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
                    } else if (区分大小写访问路径 === 'admin/ADD.txt') {
                        let 本地优选IP = await env.KV.get('ADD.txt') || 'null';
                        if (本地优选IP == 'null') 本地优选IP = (await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口))[1];
                        return new Response(本地优选IP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': request.cf.asn } });
                    } else if (访问路径 === 'admin/cf.json') {
                        return new Response(JSON.stringify(request.cf, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }

                    ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Admin_Login', config_JSON));
                    return fetch(Pages静态页面 + '/admin');
                } else if (访问路径 === 'logout' || uuidRegex.test(访问路径)) {
                    const 响应 = new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
                    响应.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
                    return 响应;
                } else if (访问路径 === 'sub') {
                    const 订阅TOKEN = await MD5MD5(host + userID);
                    if (url.searchParams.get('token') === 订阅TOKEN) {
                        config_JSON = await 读取config_JSON(env, host, userID);
                        ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_SUB', config_JSON));
                        const ua = UA.toLowerCase();
                        const expire = 4102329600;
                        const now = Date.now();
                        const today = new Date(now);
                        today.setHours(0, 0, 0, 0);
                        const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
                        let pagesSum = UD, workersSum = UD, total = 24 * 1099511627776;
                        if (config_JSON.CF.Usage.success) {
                            pagesSum = config_JSON.CF.Usage.pages;
                            workersSum = config_JSON.CF.Usage.workers;
                            total = Number.isFinite(config_JSON.CF.Usage.max) ? (config_JSON.CF.Usage.max / 1000) * 1024 : 1024 * 100;
                        }
                        const responseHeaders = {
                            "content-type": "text/plain; charset=utf-8",
                            "Profile-Update-Interval": config_JSON.优选订阅生成.SUBUpdateTime,
                            "Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
                            "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                            "Cache-Control": "no-store",
                        };

                        const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
                        let 完整优选IP = [], 其他节点LINK = '';

                        // 修复：确保 local 为 true 时正确读取自定义IP
                        if (config_JSON.优选订阅生成.local) {
                            const 完整优选列表 = config_JSON.优选订阅生成.本地IP库.随机IP 
                                ? (await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口))[0] 
                                : await env.KV.get('ADD.txt') 
                                    ? await 整理成数组(await env.KV.get('ADD.txt')) 
                                    : (await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口))[0];
                            
                            const 优选API = [], 优选IP = [], 其他节点 = [];
                            for (const 元素 of 完整优选列表) {
                                if (元素.toLowerCase().startsWith('sub://')) {
                                    优选API.push(元素);
                                } else {
                                    const subMatch = 元素.match(/sub\s*=\s*([^\s&#]+)/i);
                                    if (subMatch) {
                                        优选API.push('sub://' + subMatch[1].trim());
                                    } else if (元素.toLowerCase().startsWith('https://')) {
                                        优选API.push(元素);
                                    } else if (元素.toLowerCase().includes('://')) {
                                        if (元素.includes('#')) {
                                            const 地址备注分离 = 元素.split('#');
                                            其他节点.push(地址备注分离[0] + '#' + encodeURIComponent(decodeURIComponent(地址备注分离[1])));
                                        } else 其他节点.push(元素);
                                    } else {
                                        优选IP.push(元素);
                                    }
                                }
                            }
                            const 请求优选API内容 = await 请求优选API(优选API);
                            const 合并其他节点数组 = [...new Set(其他节点.concat(请求优选API内容[1]))];
                            其他节点LINK = 合并其他节点数组.length > 0 ? 合并其他节点数组.join('\n') + '\n' : '';
                            const 优选API的IP = 请求优选API内容[0];
                            完整优选IP = [...new Set(优选IP.concat(优选API的IP))];
                        }
                        
                        const ECHLINK参数 = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
                        
                        let 订阅内容 = 其他节点LINK + 完整优选IP.map(原始地址 => {
                            const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
                            const match = 原始地址.match(regex);

                            let 节点地址, 节点端口 = "443", 节点备注;

                            if (match) {
                                节点地址 = match[1];
                                节点端口 = match[2] || "443";
                                节点备注 = match[3] || 节点地址;
                            } else {
                                console.warn(`[订阅内容] 不规范的IP格式已忽略: ${原始地址}`);
                                return null;
                            }

                            return `${config_JSON.协议类型}://${config_JSON.UUID}@${节点地址}:${节点端口}?security=tls&type=${config_JSON.传输协议 + ECHLINK参数}&host=example.com&fp=${config_JSON.Fingerprint}&sni=example.com&path=${encodeURIComponent(config_JSON.随机路径 ? 随机路径(config_JSON.完整节点路径) : config_JSON.完整节点路径) + TLS分片参数}&encryption=none${config_JSON.跳过证书验证 ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(节点备注)}`;
                        }).filter(item => item !== null).join('\n');

                        订阅内容 = await 批量替换域名(订阅内容, config_JSON.HOSTS)

                        if (!ua.includes('mozilla')) {
                            responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
                            订阅内容 = btoa(订阅内容);
                        }

                        return new Response(订阅内容, { status: 200, headers: responseHeaders });
                    }
                } else if (访问路径 === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
            } else if (!envUUID) return fetch(Pages静态页面 + '/noKV').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
        } else if (管理员密码) {
            await 反代参数获取(request);
            return await 处理WS请求(request, userID);
        }

        let 伪装页URL = env.URL || 'nginx';
        if (伪装页URL && 伪装页URL !== 'nginx' && 伪装页URL !== '1101') {
            伪装页URL = 伪装页URL.trim().replace(/\/$/, '');
            if (!伪装页URL.match(/^https?:\/\//i)) 伪装页URL = 'https://' + 伪装页URL;
            if (伪装页URL.toLowerCase().startsWith('http://')) 伪装页URL = 'https://' + 伪装页URL.substring(7);
            try { const u = new URL(伪装页URL); 伪装页URL = u.protocol + '//' + u.host; } catch (e) { 伪装页URL = 'nginx'; }
        }
        if (伪装页URL === '1101') return new Response(await html1101(url.host, 访问IP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
        try {
            const 反代URL = new URL(伪装页URL), 新请求头 = new Headers(request.headers);
            新请求头.set('Host', 反代URL.host);
            新请求头.set('Referer', 反代URL.origin);
            新请求头.set('Origin', 反代URL.origin);
            if (!新请求头.has('User-Agent') && UA && UA !== 'null') 新请求头.set('User-Agent', UA);
            const 反代响应 = await fetch(反代URL.origin + url.pathname + url.search, { method: request.method, headers: 新请求头, body: request.body, cf: request.cf });
            const 内容类型 = 反代响应.headers.get('content-type') || '';
            if (/text|javascript|json|xml/.test(内容类型)) {
                const 响应内容 = (await 反代响应.text()).replaceAll(反代URL.host, url.host);
                return new Response(响应内容, { status: 反代响应.status, headers: { ...Object.fromEntries(反代响应.headers), 'Cache-Control': 'no-store' } });
            }
            return 反代响应;
        } catch (error) { }
        return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
    }
};

async function 处理WS请求(request, yourUUID) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);
    let 判断是否是木马 = null;
    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            if (判断是否是木马 === null) {
                const bytes = new Uint8Array(chunk);
                判断是否是木马 = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a;
            }

            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
        },
    })).catch((err) => {});

    return new Response(null, { status: 101, webSocket: clientSock });
}

function 解析木马请求(buffer, passwordPlainText) {
    const sha224Password = sha224(passwordPlainText);
    if (buffer.byteLength < 56) return { hasError: true, message: "invalid data" };
    if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) return { hasError: true, message: "invalid header format" };
    const password = new TextDecoder().decode(buffer.slice(0, 56));
    if (password !== sha224Password) return { hasError: true, message: "invalid password" };

    const socks5DataBuffer = buffer.slice(58);
    if (socks5DataBuffer.byteLength < 6) return { hasError: true, message: "invalid S5 request data" };

    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) return { hasError: true, message: "unsupported command, only TCP is allowed" };

    const atype = view.getUint8(1);
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1: // IPv4
            addressLength = 4;
            address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
            break;
        case 3: // Domain
            addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
            addressIndex += 1;
            address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            break;
        case 4: // IPv6
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `invalid addressType is ${atype}` };
    }

    if (!address) {
        return { hasError: true, message: `address is empty, addressType is ${atype}` };
    }

    const portIndex = addressIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    return {
        hasError: false,
        addressType: atype,
        port: portRemote,
        hostname: address,
        rawClientData: socks5DataBuffer.slice(portIndex + 4)
    };
}

function 解析魏烈思请求(chunk, token) {
    if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };
    const version = new Uint8Array(chunk.slice(0, 1));
    if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: 'Invalid uuid' };
    const optLen = new Uint8Array(chunk.slice(17, 18))[0];
    const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
    let isUDP = false;
    if (cmd === 1) { } else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: 'Invalid command' }; }
    const portIdx = 19 + optLen;
    const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
    let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
    const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
    switch (addressType) {
        case 1:
            addrLen = 4;
            hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.');
            break;
        case 2:
            addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0];
            addrValIdx += 1;
            hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
            break;
        case 3:
            addrLen = 16;
            const ipv6 = [];
            const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
            for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
            hostname = ipv6.join(':');
            break;
        default:
            return { hasError: true, message: `Invalid address type: ${addressType}` };
    }
    if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
    return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version };
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID) {
    console.log(`[TCP转发] 目标: ${host}:${portNum}`);

    async function connectDirect(address, port, data, 所有反代数组 = null, 反代兜底 = true) {
        let remoteSock;
        if (所有反代数组 && 所有反代数组.length > 0) {
            for (let i = 0; i < 所有反代数组.length; i++) {
                const 反代数组索引 = (缓存反代数组索引 + i) % 所有反代数组.length;
                const [反代地址, 反代端口] = 所有反代数组[反代数组索引];
                try {
                    console.log(`[反代连接] 尝试连接到: ${反代地址}:${反代端口}`);
                    remoteSock = connect({ hostname: 反代地址, port: 反代端口 });
                    await Promise.race([
                        remoteSock.opened,
                        new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), 1000))
                    ]);
                    const testWriter = remoteSock.writable.getWriter();
                    await testWriter.write(data);
                    testWriter.releaseLock();
                    console.log(`[反代连接] 成功连接到: ${反代地址}:${反代端口}`);
                    缓存反代数组索引 = 反代数组索引;
                    return remoteSock;
                } catch (err) {
                    console.log(`[反代连接] 连接失败: ${反代地址}:${反代端口}, 错误: ${err.message}`);
                    try { remoteSock?.close?.(); } catch (e) { }
                    continue;
                }
            }
        }

        if (反代兜底) {
            remoteSock = connect({ hostname: address, port: port });
            const writer = remoteSock.writable.getWriter();
            await writer.write(data);
            writer.releaseLock();
            return remoteSock;
        } else {
            closeSocketQuietly(ws);
            throw new Error('[反代连接] 所有反代连接失败，且未启用反代兜底，连接终止。');
        }
    }

    async function connecttoPry() {
        let newSocket;
        if (启用SOCKS5反代 === 'socks5') {
            console.log(`[SOCKS5代理] 代理到: ${host}:${portNum}`);
            newSocket = await socks5Connect(host, portNum, rawData);
        } else if (启用SOCKS5反代 === 'http' || 启用SOCKS5反代 === 'https') {
            console.log(`[HTTP代理] 代理到: ${host}:${portNum}`);
            newSocket = await httpConnect(host, portNum, rawData);
        } else {
            console.log(`[反代连接] 代理到: ${host}:${portNum}`);
            const 所有反代数组 = await 解析地址端口(反代IP, host, yourUUID);
            newSocket = await connectDirect(atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg=='), 1, rawData, 所有反代数组, 启用反代兜底);
        }
        remoteConnWrapper.socket = newSocket;
        newSocket.closed.catch(() => { }).finally(() => closeSocketQuietly(ws));
        connectStreams(newSocket, ws, respHeader, null);
    }

    const 验证SOCKS5白名单 = (addr) => SOCKS5白名单.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(addr));
    if (启用SOCKS5反代 && (启用SOCKS5全局反代 || 验证SOCKS5白名单(host))) {
        console.log(`[TCP转发] 启用 SOCKS5/HTTP 全局代理`);
        try {
            await connecttoPry();
        } catch (err) {
            throw err;
        }
    } else {
        try {
            console.log(`[TCP转发] 尝试直连到: ${host}:${portNum}`);
            const initialSocket = await connectDirect(host, portNum, rawData);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, connecttoPry);
        } catch (err) {
            await connecttoPry();
        }
    }
}

async function forwardataudp(udpChunk, webSocket, respHeader) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vlessHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (vlessHeader) {
                        const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
                        response.set(vlessHeader, 0);
                        response.set(chunk, vlessHeader.length);
                        webSocket.send(response.buffer);
                        vlessHeader = null;
                    } else {
                        webSocket.send(chunk);
                    }
                }
            },
        }));
    } catch (error) {}
}

function closeSocketQuietly(socket) {
    try {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close();
        }
    } catch (error) { }
}

function formatIdentifier(arr, offset = 0) {
    const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData, hasData = false;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                hasData = true;
                if (webSocket.readyState !== WebSocket.OPEN) controller.error('ws.readyState is not open');
                if (header) {
                    const response = new Uint8Array(header.length + chunk.byteLength);
                    response.set(header, 0);
                    response.set(chunk, header.length);
                    webSocket.send(response.buffer);
                    header = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            abort() { },
        })
    ).catch((err) => {
        closeSocketQuietly(webSocket);
    });
    if (!hasData && retryFunc) {
        await retryFunc();
    }
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => {
                if (!cancelled) controller.enqueue(event.data);
            });
            socket.addEventListener('close', () => {
                if (!cancelled) {
                    closeSocketQuietly(socket);
                    controller.close();
                }
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() {
            cancelled = true;
            closeSocketQuietly(socket);
        }
    });
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try {
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

async function socks5Connect(targetHost, targetPort, initialData) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
    try {
        const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
        await writer.write(authMethods);
        let response = await reader.read();
        if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');

        const selectedMethod = new Uint8Array(response.value)[1];
        if (selectedMethod === 0x02) {
            if (!username || !password) throw new Error('S5 requires authentication');
            const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password);
            const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
            await writer.write(authPacket);
            response = await reader.read();
            if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed');
        } else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

        const hostBytes = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
        await writer.write(connectPacket);
        response = await reader.read();
        if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed');

        await writer.write(initialData);
        writer.releaseLock(); reader.releaseLock();
        return socket;
    } catch (error) {
        try { writer.releaseLock(); } catch (e) { }
        try { reader.releaseLock(); } catch (e) { }
        try { socket.close(); } catch (e) { }
        throw error;
    }
}

async function httpConnect(targetHost, targetPort, initialData) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
    try {
        const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
        const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
        await writer.write(new TextEncoder().encode(request));

        let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
        while (headerEndIndex === -1 && bytesRead < 8192) {
            const { done, value } = await reader.read();
            if (done) throw new Error('Connection closed before receiving HTTP response');
            responseBuffer = new Uint8Array([...responseBuffer, ...value]);
            bytesRead = responseBuffer.length;
            const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
            if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
        }

        if (headerEndIndex === -1) throw new Error('Invalid HTTP response');
        const statusCode = parseInt(new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/)[1]);
        if (statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

        await writer.write(initialData);
        writer.releaseLock(); reader.releaseLock();
        return socket;
    } catch (error) {
        try { writer.releaseLock(); } catch (e) { }
        try { reader.releaseLock(); } catch (e) { }
        try { socket.close(); } catch (e) { }
        throw error;
    }
}

async function 请求日志记录(env, request, 访问IP, 请求类型 = "Get_SUB", config_JSON) {
    const KV容量限制 = 4;
    try {
        const 当前时间 = new Date();
        const 日志内容 = { TYPE: 请求类型, IP: 访问IP, ASN: `AS${request.cf.asn || '0'} ${request.cf.asOrganization || 'Unknown'}`, CC: `${request.cf.country || 'N/A'} ${request.cf.city || 'N/A'}`, URL: request.url, UA: request.headers.get('User-Agent') || 'Unknown', TIME: 当前时间.getTime() };
        let 日志数组 = [];
        const 现有日志 = await env.KV.get('log.json');
        if (现有日志) {
            try {
                日志数组 = JSON.parse(现有日志);
                if (!Array.isArray(日志数组)) { 日志数组 = [日志内容]; }
                else if (请求类型 !== "Get_SUB") {
                    const 三十分钟前时间戳 = 当前时间.getTime() - 30 * 60 * 1000;
                    if (日志数组.some(log => log.TYPE !== "Get_SUB" && log.IP === 访问IP && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= 三十分钟前时间戳)) return;
                    日志数组.push(日志内容);
                    while (JSON.stringify(日志数组, null, 2).length > KV容量限制 * 1024 * 1024 && 日志数组.length > 0) 日志数组.shift();
                } else {
                    日志数组.push(日志内容);
                    while (JSON.stringify(日志数组, null, 2).length > KV容量限制 * 1024 * 1024 && 日志数组.length > 0) 日志数组.shift();
                }
                if (config_JSON.TG.启用) {
                    try {
                        const TG_TXT = await env.KV.get('tg.json');
                        const TG_JSON = JSON.parse(TG_TXT);
                        await sendMessage(TG_JSON.BotToken, TG_JSON.ChatID, 日志内容, config_JSON);
                    } catch (error) { console.error(`读取tg.json出错: ${error.message}`) }
                }
            } catch (e) { 日志数组 = [日志内容]; }
        } else { 日志数组 = [日志内容]; }
        await env.KV.put('log.json', JSON.stringify(日志数组, null, 2));
    } catch (error) { console.error(`日志记录失败: ${error.message}`); }
}

async function sendMessage(BotToken, ChatID, 日志内容, config_JSON) {
    if (!BotToken || !ChatID) return;

    try {
        const 请求时间 = new Date(日志内容.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
        const 请求URL = new URL(日志内容.URL);
        const msg = `<b>#${config_JSON.优选订阅生成.SUBNAME} 日志通知</b>\n\n` +
            `📌 <b>类型：</b>#${日志内容.TYPE}\n` +
            `🌐 <b>IP：</b><code>${日志内容.IP}</code>\n` +
            `📍 <b>位置：</b>${日志内容.CC}\n` +
            `🏢 <b>ASN：</b>${日志内容.ASN}\n` +
            `🔗 <b>域名：</b><code>${请求URL.host}</code>\n` +
            `🔍 <b>路径：</b><code>${请求URL.pathname + 请求URL.search}</code>\n` +
            `🤖 <b>UA：</b><code>${日志内容.UA}</code>\n` +
            `📅 <b>时间：</b>${请求时间}\n` +
            `${config_JSON.CF.Usage.success ? `📊 <b>请求用量：</b>${config_JSON.CF.Usage.total}/${config_JSON.CF.Usage.max} <b>${((config_JSON.CF.Usage.total / config_JSON.CF.Usage.max) * 100).toFixed(2)}%</b>\n` : ''}`;

        const url = `https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
        return fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'Accept-Encoding': 'gzip, deflate, br',
                'User-Agent': 日志内容.UA || 'Unknown',
            }
        });
    } catch (error) { console.error('Error sending message:', error) }
}

function 掩码敏感信息(文本, 前缀长度 = 3, 后缀长度 = 2) {
    if (!文本 || typeof 文本 !== 'string') return 文本;
    if (文本.length <= 前缀长度 + 后缀长度) return 文本;
    const 前缀 = 文本.slice(0, 前缀长度);
    const 后缀 = 文本.slice(-后缀长度);
    const 星号数量 = 文本.length - 前缀长度 - 后缀长度;
    return `${前缀}${'*'.repeat(星号数量)}${后缀}`;
}

async function MD5MD5(文本) {
    const 编码器 = new TextEncoder();
    const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
    const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
    const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');
    const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
    const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
    const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');
    return 第二次十六进制.toLowerCase();
}

function 随机路径(完整节点路径 = "/") {
    const 常用路径目录 = ["about", "account", "acg", "act", "activity", "ad", "ads", "ajax", "album", "albums", "anime", "api", "app", "apps", "archive", "archives", "article", "articles", "ask", "auth", "avatar", "bbs", "bd", "blog", "blogs", "book", "books", "bt", "buy", "cart", "category", "categories", "cb", "channel", "channels", "chat", "china", "city", "class", "classify", "clip", "clips", "club", "cn", "code", "collect", "collection", "comic", "comics", "community", "company", "config", "contact", "content", "course", "courses", "cp", "data", "detail", "details", "dh", "directory", "discount", "discuss", "dl", "dload", "doc", "docs", "document", "documents", "doujin", "download", "downloads", "drama", "edu", "en", "ep", "episode", "episodes", "event", "events", "f", "faq", "favorite", "favourites", "favs", "feedback", "file", "files", "film", "films", "forum", "forums", "friend", "friends", "game", "games", "gif", "go", "go.html", "go.php", "group", "groups", "help", "home", "hot", "htm", "html", "image", "images", "img", "index", "info", "intro", "item", "items", "ja", "jp", "jump", "jump.html", "jump.php", "jumping", "knowledge", "lang", "lesson", "lessons", "lib", "library", "link", "links", "list", "live", "lives", "m", "mag", "magnet", "mall", "manhua", "map", "member", "members", "message", "messages", "mobile", "movie", "movies", "music", "my", "new", "news", "note", "novel", "novels", "online", "order", "out", "out.html", "out.php", "outbound", "p", "page", "pages", "pay", "payment", "pdf", "photo", "photos", "pic", "pics", "picture", "pictures", "play", "player", "playlist", "post", "posts", "product", "products", "program", "programs", "project", "qa", "question", "rank", "ranking", "read", "readme", "redirect", "redirect.html", "redirect.php", "reg", "register", "res", "resource", "retrieve", "sale", "search", "season", "seasons", "section", "seller", "series", "service", "services", "setting", "settings", "share", "shop", "show", "shows", "site", "soft", "sort", "source", "special", "star", "stars", "static", "stock", "store", "stream", "streaming", "streams", "student", "study", "tag", "tags", "task", "teacher", "team", "tech", "temp", "test", "thread", "tool", "tools", "topic", "topics", "torrent", "trade", "travel", "tv", "txt", "type", "u", "upload", "uploads", "url", "urls", "user", "users", "v", "version", "video", "videos", "view", "vip", "vod", "watch", "web", "wenku", "wiki", "work", "www", "zh", "zh-cn", "zh-tw", "zip"];
    const 随机数 = Math.floor(Math.random() * 3 + 1);
    const 随机路径 = 常用路径目录.sort(() => 0.5 - Math.random()).slice(0, 随机数).join('/');
    if (完整节点路径 === "/") return `/${随机路径}`;
    else return `/${随机路径 + 完整节点路径.replace('/?', '?')}`;
}

function 随机替换通配符(h) {
    if (!h?.includes('*')) return h;
    const 字符集 = 'abcdefghijklmnopqrstuvwxyz0123456789';
    return h.replace(/\*/g, () => {
        let s = '';
        for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++)
            s += 字符集[Math.floor(Math.random() * 36)];
        return s;
    });
}

function 批量替换域名(内容, hosts, 每组数量 = 2) {
    const 打乱后数组 = [...hosts].sort(() => Math.random() - 0.5);
    let count = 0, currentRandomHost = null;
    return 内容.replace(/example\.com/g, () => {
        if (count % 每组数量 === 0) currentRandomHost = 随机替换通配符(打乱后数组[Math.floor(count / 每组数量) % 打乱后数组.length]);
        count++;
        return currentRandomHost;
    });
}

async function DoH查询(域名, 记录类型, DoH解析服务 = "https://cloudflare-dns.com/dns-query") {
    const 开始时间 = performance.now();
    console.log(`[DoH查询] 开始查询 ${域名} ${记录类型} via ${DoH解析服务}`);
    try {
        const 类型映射 = { 'A': 1, 'NS': 2, 'CNAME': 5, 'MX': 15, 'TXT': 16, 'AAAA': 28, 'SRV': 33, 'HTTPS': 65 };
        const qtype = 类型映射[记录类型.toUpperCase()] || 1;

        const 编码域名 = (name) => {
            const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
            const bufs = [];
            for (const label of parts) {
                const enc = new TextEncoder().encode(label);
                bufs.push(new Uint8Array([enc.length]), enc);
            }
            bufs.push(new Uint8Array([0]));
            const total = bufs.reduce((s, b) => s + b.length, 0);
            const result = new Uint8Array(total);
            let off = 0;
            for (const b of bufs) { result.set(b, off); off += b.length; }
            return result;
        };

        const qname = 编码域名(域名);
        const query = new Uint8Array(12 + qname.length + 4);
        const qview = new DataView(query.buffer);
        qview.setUint16(0, 0);
        qview.setUint16(2, 0x0100);
        qview.setUint16(4, 1);
        query.set(qname, 12);
        qview.setUint16(12 + qname.length, qtype);
        qview.setUint16(12 + qname.length + 2, 1);

        console.log(`[DoH查询] 发送查询报文 ${域名} via ${DoH解析服务} (type=${qtype}, ${query.length}字节)`);
        const response = await fetch(DoH解析服务, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/dns-message',
                'Accept': 'application/dns-message',
            },
            body: query,
        });
        if (!response.ok) {
            console.warn(`[DoH查询] 请求失败 ${域名} ${记录类型} via ${DoH解析服务} 响应代码:${response.status}`);
            return [];
        }

        const buf = new Uint8Array(await response.arrayBuffer());
        const dv = new DataView(buf.buffer);
        const qdcount = dv.getUint16(4);
        const ancount = dv.getUint16(6);
        console.log(`[DoH查询] 收到响应 ${域名} ${记录类型} via ${DoH解析服务} (${buf.length}字节, ${ancount}条应答)`);

        const 解析域名 = (pos) => {
            const labels = [];
            let p = pos, jumped = false, endPos = -1, safe = 128;
            while (p < buf.length && safe-- > 0) {
                const len = buf[p];
                if (len === 0) { if (!jumped) endPos = p + 1; break; }
                if ((len & 0xC0) === 0xC0) {
                    if (!jumped) endPos = p + 2;
                    p = ((len & 0x3F) << 8) | buf[p + 1];
                    jumped = true;
                    continue;
                }
                labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
                p += len + 1;
            }
            if (endPos === -1) endPos = p + 1;
            return [labels.join('.'), endPos];
        };

        let offset = 12;
        for (let i = 0; i < qdcount; i++) {
            const [, end] = 解析域名(offset);
            offset = /** @type {number} */ (end) + 4;
        }

        const answers = [];
        for (let i = 0; i < ancount && offset < buf.length; i++) {
            const [name, nameEnd] = 解析域名(offset);
            offset = /** @type {number} */ (nameEnd);
            const type = dv.getUint16(offset); offset += 2;
            offset += 2;
            const ttl = dv.getUint32(offset); offset += 4;
            const rdlen = dv.getUint16(offset); offset += 2;
            const rdata = buf.slice(offset, offset + rdlen);
            offset += rdlen;

            let data;
            if (type === 1 && rdlen === 4) {
                data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
            } else if (type === 28 && rdlen === 16) {
                const segs = [];
                for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
                data = segs.join(':');
            } else if (type === 16) {
                let tOff = 0;
                const parts = [];
                while (tOff < rdlen) {
                    const tLen = rdata[tOff++];
                    parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
                    tOff += tLen;
                }
                data = parts.join('');
            } else if (type === 5) {
                const [cname] = 解析域名(offset - rdlen);
                data = cname;
            } else {
                data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
            }
            answers.push({ name, type, TTL: ttl, data, rdata });
        }
        const 耗时 = (performance.now() - 开始时间).toFixed(2);
        console.log(`[DoH查询] 查询完成 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms 共${answers.length}条结果`);
        return answers;
    } catch (error) {
        const 耗时 = (performance.now() - 开始时间).toFixed(2);
        console.error(`[DoH查询] 查询失败 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms:`, error);
        return [];
    }
}

async function getECH(host) {
    try {
        const answers = await DoH查询(host, 'HTTPS');
        if (!answers.length) return '';
        for (const ans of answers) {
            if (ans.type !== 65 || !ans.rdata) continue;
            const bytes = ans.rdata;
            let offset = 2;
            while (offset < bytes.length) {
                const len = bytes[offset];
                if (len === 0) { offset++; break; }
                offset += len + 1;
            }
            while (offset + 4 <= bytes.length) {
                const key = (bytes[offset] << 8) | bytes[offset + 1];
                const len = (bytes[offset + 2] << 8) | bytes[offset + 3];
                offset += 4;
                if (key === 5) return btoa(String.fromCharCode(...bytes.slice(offset, offset + len)));
                offset += len;
            }
        }
        return '';
    } catch {
        return '';
    }
}

async function 读取config_JSON(env, hostname, userID, 重置配置 = false) {
    const _p = atob("UFJPWFlJUA==");
    const host = hostname, CM_DoH = "https://doh.cmliussss.net/CMLiussss", 占位符 = '{{IP:PORT}}', 初始化开始时间 = performance.now(), 默认配置JSON = {
        TIME: new Date().toISOString(),
        HOST: host,
        HOSTS: [hostname],
        UUID: userID,
        PATH: "/",
        协议类型: "v" + "le" + "ss",
        传输协议: "ws",
        跳过证书验证: false,
        启用0RTT: false,
        TLS分片: null,
        随机路径: false,
        ECH: false,
        ECHConfig: {
            DNS: CM_DoH,
            SNI: null,
        },
        Fingerprint: "chrome",
        优选订阅生成: {
            local: true,
            本地IP库: {
                随机IP: true,
                随机数量: 16,
                指定端口: -1,
            },
            SUB: null,
            SUBNAME: "edge" + "tunnel",
            SUBUpdateTime: 3,
            TOKEN: await MD5MD5(hostname + userID),
        },
        反代: {
            [_p]: "auto",
            SOCKS5: {
                启用: 启用SOCKS5反代,
                全局: 启用SOCKS5全局反代,
                账号: 我的SOCKS5账号,
                白名单: SOCKS5白名单,
            },
            路径模板: {
                [_p]: "proxyip=" + 占位符,
                SOCKS5: {
                    全局: "socks5://" + 占位符,
                    标准: "socks5=" + 占位符
                },
                HTTP: {
                    全局: "http://" + 占位符,
                    标准: "http=" + 占位符
                },
            },
        },
        TG: {
            启用: false,
            BotToken: null,
            ChatID: null,
        },
        CF: {
            Email: null,
            GlobalAPIKey: null,
            AccountID: null,
            APIToken: null,
            UsageAPI: null,
            Usage: {
                success: false,
                pages: 0,
                workers: 0,
                total: 0,
                max: 100000,
            },
        }
    };

    try {
        let configJSON = await env.KV.get('config.json');
        if (!configJSON || 重置配置 == true) {
            await env.KV.put('config.json', JSON.stringify(默认配置JSON, null, 2));
            config_JSON = 默认配置JSON;
        } else {
            config_JSON = JSON.parse(configJSON);
        }
    } catch (error) {
        console.error(`读取config_JSON出错: ${error.message}`);
        config_JSON = 默认配置JSON;
    }

    config_JSON.HOST = host;
    if (!config_JSON.HOSTS) config_JSON.HOSTS = [hostname];
    if (env.HOST) config_JSON.HOSTS = (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
    config_JSON.UUID = userID;
    if (!config_JSON.随机路径) config_JSON.随机路径 = false;
    if (!config_JSON.启用0RTT) config_JSON.启用0RTT = false;

    if (env.PATH) config_JSON.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
    else if (!config_JSON.PATH) config_JSON.PATH = '/';

    if (!config_JSON.反代.路径模板?.[_p]) {
        config_JSON.反代.路径模板 = {
            [_p]: "proxyip=" + 占位符,
            SOCKS5: {
                全局: "socks5://" + 占位符,
                标准: "socks5=" + 占位符
            },
            HTTP: {
                全局: "http://" + 占位符,
                标准: "http=" + 占位符
            },
        };
    }

    const 代理配置 = config_JSON.反代.路径模板[config_JSON.反代.SOCKS5.启用?.toUpperCase()];

    let 路径反代参数 = '';
    if (代理配置 && config_JSON.反代.SOCKS5.账号) 路径反代参数 = (config_JSON.反代.SOCKS5.全局 ? 代理配置.全局 : 代理配置.标准).replace(占位符, config_JSON.反代.SOCKS5.账号);
    else if (config_JSON.反代[_p] !== 'auto') 路径反代参数 = config_JSON.反代.路径模板[_p].replace(占位符, config_JSON.反代[_p]);

    let 反代查询参数 = '';
    if (路径反代参数.includes('?')) {
        const [反代路径部分, 反代查询部分] = 路径反代参数.split('?');
        路径反代参数 = 反代路径部分;
        反代查询参数 = 反代查询部分;
    }

    config_JSON.PATH = config_JSON.PATH.replace(路径反代参数, '').replace('//', '/');
    const normalizedPath = config_JSON.PATH === '/' ? '' : config_JSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
    const [路径部分, ...查询数组] = normalizedPath.split('?');
    const 查询部分 = 查询数组.length ? '?' + 查询数组.join('?') : '';
    const 最终查询部分 = 反代查询参数 ? (查询部分 ? 查询部分 + '&' + 反代查询参数 : '?' + 反代查询参数) : 查询部分;
    config_JSON.完整节点路径 = (路径部分 || '/') + (路径部分 && 路径反代参数 ? '/' : '') + 路径反代参数 + 最终查询部分 + (config_JSON.启用0RTT ? (最终查询部分 ? '&' : '?') + 'ed=2560' : '');

    if (!config_JSON.TLS分片 && config_JSON.TLS分片 !== null) config_JSON.TLS分片 = null;
    const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
    if (!config_JSON.Fingerprint) config_JSON.Fingerprint = "chrome";
    if (!config_JSON.ECH) config_JSON.ECH = false;
    if (!config_JSON.ECHConfig) config_JSON.ECHConfig = { DNS: CM_DoH, SNI: null };
    const ECHLINK参数 = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
    config_JSON.LINK = `${config_JSON.协议类型}://${userID}@${host}:443?security=tls&type=${config_JSON.传输协议 + ECHLINK参数}&host=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&path=${encodeURIComponent(config_JSON.随机路径 ? 随机路径(config_JSON.完整节点路径) : config_JSON.完整节点路径) + TLS分片参数}&encryption=none${config_JSON.跳过证书验证 ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
    config_JSON.优选订阅生成.TOKEN = await MD5MD5(hostname + userID);

    const 初始化TG_JSON = { BotToken: null, ChatID: null };
    config_JSON.TG = { 启用: config_JSON.TG.启用 ? config_JSON.TG.启用 : false, ...初始化TG_JSON };
    try {
        const TG_TXT = await env.KV.get('tg.json');
        if (!TG_TXT) {
            await env.KV.put('tg.json', JSON.stringify(初始化TG_JSON, null, 2));
        } else {
            const TG_JSON = JSON.parse(TG_TXT);
            config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
            config_JSON.TG.BotToken = TG_JSON.BotToken ? 掩码敏感信息(TG_JSON.BotToken) : null;
        }
    } catch (error) {
        console.error(`读取tg.json出错: ${error.message}`);
    }

    const 初始化CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
    config_JSON.CF = { ...初始化CF_JSON, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
    try {
        const CF_TXT = await env.KV.get('cf.json');
        if (!CF_TXT) {
            await env.KV.put('cf.json', JSON.stringify(初始化CF_JSON, null, 2));
        } else {
            const CF_JSON = JSON.parse(CF_TXT);
            if (CF_JSON.UsageAPI) {
                try {
                    const response = await fetch(CF_JSON.UsageAPI);
                    const Usage = await response.json();
                    config_JSON.CF.Usage = Usage;
                } catch (err) {
                    console.error(`请求 CF_JSON.UsageAPI 失败: ${err.message}`);
                }
            } else {
                config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
                config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? 掩码敏感信息(CF_JSON.GlobalAPIKey) : null;
                config_JSON.CF.AccountID = CF_JSON.AccountID ? 掩码敏感信息(CF_JSON.AccountID) : null;
                config_JSON.CF.APIToken = CF_JSON.APIToken ? 掩码敏感信息(CF_JSON.APIToken) : null;
                config_JSON.CF.UsageAPI = null;
                const Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
                config_JSON.CF.Usage = Usage;
            }
        }
    } catch (error) {
        console.error(`读取cf.json出错: ${error.message}`);
    }

    config_JSON.加载时间 = (performance.now() - 初始化开始时间).toFixed(2) + 'ms';
    return config_JSON;
}

async function 生成随机IP(request, count = 16, 指定端口 = -1) {
    const ISP配置 = {
        '9808': { file: 'cmcc', name: 'CF移动优选' },
        '4837': { file: 'cu', name: 'CF联通优选' },
        '17623': { file: 'cu', name: 'CF联通优选' },
        '17816': { file: 'cu', name: 'CF联通优选' },
        '4134': { file: 'ct', name: 'CF电信优选' },
    };
    const asn = request.cf.asn, isp = ISP配置[asn];
    const cidr_url = isp ? `https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR/${isp.file}.txt` : 'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt';
    const cfname = isp?.name || 'CF官方优选';
    const cfport = [443, 2053, 2083, 2087, 2096, 8443];
    let cidrList = [];
    try { const res = await fetch(cidr_url); cidrList = res.ok ? await 整理成数组(await res.text()) : ['104.16.0.0/13']; } catch { cidrList = ['104.16.0.0/13']; }

    const generateRandomIPFromCIDR = (cidr) => {
        const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength), hostBits = 32 - prefix;
        const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
        const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
        const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
        return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
    };

    const randomIPs = Array.from({ length: count }, () => {
        const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
        return `${ip}:${指定端口 === -1 ? cfport[Math.floor(Math.random() * cfport.length)] : 指定端口}#${cfname}`;
    });
    return [randomIPs, randomIPs.join('\n')];
}

async function 整理成数组(内容) {
    var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
    if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
    if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
    const 地址数组 = 替换后的内容.split(',');
    return 地址数组;
}

function isValidBase64(str) {
    if (typeof str !== 'string') return false;
    const cleanStr = str.replace(/\s/g, '');
    if (cleanStr.length === 0 || cleanStr.length % 4 !== 0) return false;
    const base64Regex = /^[A-Za-z0-9+/]+={0,2}$/;
    if (!base64Regex.test(cleanStr)) return false;
    try {
        atob(cleanStr);
        return true;
    } catch {
        return false;
    }
}

function base64Decode(str) {
    const bytes = new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
    const decoder = new TextDecoder('utf-8');
    return decoder.decode(bytes);
}

async function 获取优选订阅生成器数据(优选订阅生成器HOST) {
    let 优选IP = [], 其他节点LINK = '', 格式化HOST = 优选订阅生成器HOST.replace(/^sub:\/\//i, 'https://');
    if (!/^https?:\/\//i.test(格式化HOST)) 格式化HOST = `https://${格式化HOST}`;

    try {
        const url = new URL(格式化HOST);
        格式化HOST = url.origin;
    } catch (error) {
        优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST}优选订阅生成器格式化异常:${error.message}`);
        return [优选IP, 其他节点LINK];
    }

    const 优选订阅生成器URL = `${格式化HOST}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;

    try {
        const response = await fetch(优选订阅生成器URL, {
            headers: { 'User-Agent': 'v2rayN/edge' + 'tunnel (https://github.com/cmliu/edge' + 'tunnel)' }
        });

        if (!response.ok) {
            优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST}优选订阅生成器异常:${response.statusText}`);
            return [优选IP, 其他节点LINK];
        }

        const 优选订阅生成器返回订阅内容 = atob(await response.text());
        const 订阅行列表 = 优选订阅生成器返回订阅内容.includes('\r\n')
            ? 优选订阅生成器返回订阅内容.split('\r\n')
            : 优选订阅生成器返回订阅内容.split('\n');

        for (const 行内容 of 订阅行列表) {
            if (!行内容.trim()) continue;
            if (行内容.includes('00000000-0000-4000-8000-000000000000') && 行内容.includes('example.com')) {
                const 地址匹配 = 行内容.match(/:\/\/[^@]+@([^?]+)/);
                if (地址匹配) {
                    let 地址端口 = 地址匹配[1], 备注 = '';
                    const 备注匹配 = 行内容.match(/#(.+)$/);
                    if (备注匹配) 备注 = '#' + decodeURIComponent(备注匹配[1]);
                    优选IP.push(地址端口 + 备注);
                }
            } else {
                其他节点LINK += 行内容 + '\n';
            }
        }
    } catch (error) {
        优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST}优选订阅生成器异常:${error.message}`);
    }

    return [优选IP, 其他节点LINK];
}

async function 请求优选API(urls, 默认端口 = '443', 超时时间 = 3000) {
    if (!urls?.length) return [[], [], []];
    const results = new Set();
    let 订阅链接响应的明文LINK内容 = '', 需要订阅转换订阅URLs = [];
    await Promise.allSettled(urls.map(async (url) => {
        if (url.toLowerCase().startsWith('sub://')) {
            try {
                const [优选IP, 其他节点LINK] = await 获取优选订阅生成器数据(url);
                for (const ip of 优选IP) results.add(ip);
                if (其他节点LINK) 订阅链接响应的明文LINK内容 += 其他节点LINK;
            } catch (e) { }
            return;
        }

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 超时时间);
            const response = await fetch(url, { signal: controller.signal });
            clearTimeout(timeoutId);
            let text = '';
            try {
                const buffer = await response.arrayBuffer();
                const contentType = (response.headers.get('content-type') || '').toLowerCase();
                const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

                let decoders = ['utf-8', 'gb2312'];
                if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
                    decoders = ['gb2312', 'utf-8'];
                }

                let decodeSuccess = false;
                for (const decoder of decoders) {
                    try {
                        const decoded = new TextDecoder(decoder).decode(buffer);
                        if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
                            text = decoded;
                            decodeSuccess = true;
                            break;
                        } else if (decoded && decoded.length > 0) {
                            continue;
                        }
                    } catch (e) {
                        continue;
                    }
                }

                if (!decodeSuccess) {
                    text = await response.text();
                }

                if (!text || text.trim().length === 0) {
                    return;
                }
            } catch (e) {
                console.error('Failed to decode response:', e);
                return;
            }

            const 预处理订阅明文内容 = isValidBase64(text) ? base64Decode(text) : text;
            if (预处理订阅明文内容.split('#')[0].includes('://')) {
                订阅链接响应的明文LINK内容 += 预处理订阅明文内容 + '\n';
                return;
            }

            const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
            const isCSV = lines.length > 1 && lines[0].includes(',');
            const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
            if (!isCSV) {
                lines.forEach(line => {
                    const hashIndex = line.indexOf('#');
                    const [hostPart, remark] = hashIndex > -1 ? [line.substring(0, hashIndex), line.substring(hashIndex)] : [line, ''];
                    let hasPort = false;
                    if (hostPart.startsWith('[')) {
                        hasPort = /\]:(\d+)$/.test(hostPart);
                    } else {
                        const colonIndex = hostPart.lastIndexOf(':');
                        hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
                    }
                    const port = new URL(url).searchParams.get('port') || 默认端口;
                    results.add(hasPort ? line : `${hostPart}:${port}${remark}`);
                });
            } else {
                const headers = lines[0].split(',').map(h => h.trim());
                const dataLines = lines.slice(1);
                if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
                    const ipIdx = headers.indexOf('IP地址'), portIdx = headers.indexOf('端口');
                    const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') :
                        headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心');
                    const tlsIdx = headers.indexOf('TLS');
                    dataLines.forEach(line => {
                        const cols = line.split(',').map(c => c.trim());
                        if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
                        const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
                        results.add(`${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`);
                    });
                } else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('延迟')) && headers.some(h => h.includes('下载速度'))) {
                    const ipIdx = headers.findIndex(h => h.includes('IP'));
                    const delayIdx = headers.findIndex(h => h.includes('延迟'));
                    const speedIdx = headers.findIndex(h => h.includes('下载速度'));
                    const port = new URL(url).searchParams.get('port') || 默认端口;
                    dataLines.forEach(line => {
                        const cols = line.split(',').map(c => c.trim());
                        const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
                        results.add(`${wrappedIP}:${port}#CF优选 ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`);
                    });
                }
            }
        } catch (e) { }
    }));
    const LINK数组 = 订阅链接响应的明文LINK内容.trim() ? [...new Set(订阅链接响应的明文LINK内容.split(/\r?\n/).filter(line => line.trim() !== ''))] : [];
    return [Array.from(results), LINK数组, 需要订阅转换订阅URLs];
}

async function 反代参数获取(request) {
    const url = new URL(request.url);
    const { pathname, searchParams } = url;
    const pathLower = pathname.toLowerCase();

    我的SOCKS5账号 = searchParams.get('socks5') || searchParams.get('http') || null;
    启用SOCKS5全局反代 = searchParams.has('globalproxy') || false;

    const 解析代理URL = (proxyUrl, 默认全局 = true) => {
        const protocolMatch = proxyUrl.match(/^(socks5|http):\/\/(.+)$/i);
        if (!protocolMatch) return false;
        启用SOCKS5反代 = protocolMatch[1].toLowerCase();
        我的SOCKS5账号 = protocolMatch[2].split('/')[0];
        启用SOCKS5全局反代 = 默认全局 || 启用SOCKS5全局反代;
        return true;
    };

    const 提取路径值 = (rawValue) => {
        if (rawValue.includes('://')) {
            const protocolPart = rawValue.split('://');
            if (protocolPart.length === 2) {
                const [protocol, afterProtocol] = protocolPart;
                const firstSlashIndex = afterProtocol.indexOf('/');
                if (firstSlashIndex > 0) {
                    return protocol + '://' + afterProtocol.substring(0, firstSlashIndex);
                }
            }
        } else {
            const firstSlashIndex = rawValue.indexOf('/');
            if (firstSlashIndex > 0) {
                return rawValue.substring(0, firstSlashIndex);
            }
        }
        return rawValue;
    };

    let socksMatch, proxyMatch;
    if (searchParams.has('proxyip')) {
        const 路参IP = searchParams.get('proxyip');
        if (解析代理URL(路参IP)) { }
        else {
            反代IP = 路参IP.includes(',') ? 路参IP.split(',')[Math.floor(Math.random() * 路参IP.split(',').length)] : 路参IP;
            启用反代兜底 = false;
            return;
        }
    }
    else if ((socksMatch = pathname.match(/\/(socks5?|http):\/?\/?([^/?#\s]+)/i))) {
        启用SOCKS5反代 = socksMatch[1].toLowerCase() === 'http' ? 'http' : 'socks5';
        我的SOCKS5账号 = socksMatch[2].split('/')[0];
        启用SOCKS5全局反代 = true;
    }
    else if ((socksMatch = pathname.match(/\/(g?s5|socks5|g?http)=([^/?#\s]+)/i))) {
        const type = socksMatch[1].toLowerCase();
        我的SOCKS5账号 = socksMatch[2].split('/')[0];
        启用SOCKS5反代 = type.includes('http') ? 'http' : 'socks5';
        启用SOCKS5全局反代 = type.startsWith('g') || 启用SOCKS5全局反代;
    }
    else if ((proxyMatch = pathLower.match(/\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/))) {
        let 路参IP = 提取路径值(proxyMatch[2]);
        if (!解析代理URL(路参IP)) {
            反代IP = 路参IP.includes(',') ? 路参IP.split(',')[Math.floor(Math.random() * 路参IP.split(',').length)] : 路参IP;
            启用反代兜底 = false;
            return;
        }
    }

    if (我的SOCKS5账号) {
        try {
            parsedSocks5Address = await 获取SOCKS5账号(我的SOCKS5账号);
            启用SOCKS5反代 = searchParams.get('http') ? 'http' : (启用SOCKS5反代 || 'socks5');
        } catch (err) {
            console.error('解析SOCKS5地址失败:', err.message);
            启用SOCKS5反代 = null;
        }
    } else 启用SOCKS5反代 = null;
}

async function 获取SOCKS5账号(address) {
    if (address.includes('@')) {
        const lastAtIndex = address.lastIndexOf('@');
        let userPassword = address.substring(0, lastAtIndex).replaceAll('%3D', '=');
        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
        address = `${userPassword}@${address.substring(lastAtIndex + 1)}`;
    }
    const atIndex = address.lastIndexOf("@");
    const [hostPart, authPart] = atIndex === -1 ? [address, undefined] : [address.substring(atIndex + 1), address.substring(0, atIndex)];

    let username, password;
    if (authPart) {
        [username, password] = authPart.split(":");
        if (!password) throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
    }

    let hostname, port;
    if (hostPart.includes("]:")) {
        [hostname, port] = [hostPart.split("]:")[0] + "]", Number(hostPart.split("]:")[1].replace(/[^\d]/g, ''))];
    } else if (hostPart.startsWith("[")) {
        [hostname, port] = [hostPart, 80];
    } else {
        const parts = hostPart.split(":");
        [hostname, port] = parts.length === 2 ? [parts[0], Number(parts[1].replace(/[^\d]/g, ''))] : [hostPart, 80];
    }

    if (isNaN(port)) throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    if (hostname.includes(":") && !/^\[.*\]$/.test(hostname)) throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');

    return { username, password, hostname, port };
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
    const API = "https://api.cloudflare.com/client/v4";
    const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
    const cfg = { "Content-Type": "application/json" };

    try {
        if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

        if (!AccountID) {
            const r = await fetch(`${API}/accounts`, {
                method: "GET",
                headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
            });
            if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
            const d = await r.json();
            if (!d?.result?.length) throw new Error("未找到账户");
            const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
            AccountID = d.result[idx >= 0 ? idx : 0]?.id;
        }

        const now = new Date();
        now.setUTCHours(0, 0, 0, 0);
        const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

        const res = await fetch(`${API}/graphql`, {
            method: "POST",
            headers: hdr,
            body: JSON.stringify({
                query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
                    viewer { accounts(filter: {accountTag: $AccountID}) {
                        pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
                        workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
                    } }
                }`,
                variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
            })
        });

        if (!res.ok) throw new Error(`查询失败: ${res.status}`);
        const result = await res.json();
        if (result.errors?.length) throw new Error(result.errors[0].message);

        const acc = result?.data?.viewer?.accounts?.[0];
        if (!acc) throw new Error("未找到账户数据");

        const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
        const workers = sum(acc.workersInvocationsAdaptive);
        const total = pages + workers;
        const max = 100000;
        console.log(`统计结果 - Pages: ${pages}, Workers: ${workers}, 总计: ${total}, 上限: 100000`);
        return { success: true, pages, workers, total, max };

    } catch (error) {
        console.error('获取使用量错误:', error.message);
        return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
    }
}

function sha224(s) {
    const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
    s = unescape(encodeURIComponent(s));
    const l = s.length * 8; s += String.fromCharCode(0x80);
    while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
    const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
    s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
    const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
    for (let i = 0; i < w.length; i += 16) {
        const x = new Array(64).fill(0);
        for (let j = 0; j < 16; j++)x[j] = w[i + j];
        for (let j = 16; j < 64; j++) {
            const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
            const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
            x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
        }
        let [a, b, c, d, e, f, g, h0] = h;
        for (let j = 0; j < 64; j++) {
            const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
            const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
            h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
        }
        for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
    }
    let hex = '';
    for (let i = 0; i < 7; i++) {
        for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
    }
    return hex;
}

async function 解析地址端口(proxyIP, 目标域名 = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
    if (!缓存反代IP || !缓存反代解析数组 || 缓存反代IP !== proxyIP) {
        proxyIP = proxyIP.toLowerCase();

        function 解析地址端口字符串(str) {
            let 地址 = str, 端口 = 443;
            if (str.includes(']:')) {
                const parts = str.split(']:');
                地址 = parts[0] + ']';
                端口 = parseInt(parts[1], 10) || 端口;
            } else if (str.includes(':') && !str.startsWith('[')) {
                const colonIndex = str.lastIndexOf(':');
                地址 = str.slice(0, colonIndex);
                端口 = parseInt(str.slice(colonIndex + 1), 10) || 端口;
            }
            return [地址, 端口];
        }

        let 所有反代数组 = [];

        if (proxyIP.includes('.william')) {
            try {
                let txtRecords = await DoH查询(proxyIP, 'TXT');
                let txtData = txtRecords.filter(r => r.type === 16).map(r => /** @type {string} */ (r.data));
                if (txtData.length === 0) {
                    console.log(`[反代解析] 默认DoH未获取到TXT记录，切换Google DoH重试 ${proxyIP}`);
                    txtRecords = await DoH查询(proxyIP, 'TXT', 'https://dns.google/dns-query');
                    txtData = txtRecords.filter(r => r.type === 16).map(r => /** @type {string} */ (r.data));
                }
                if (txtData.length > 0) {
                    let data = txtData[0];
                    if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
                    const prefixes = data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
                    所有反代数组 = prefixes.map(prefix => 解析地址端口字符串(prefix));
                }
            } catch (error) {
                console.error('解析William域名失败:', error);
            }
        } else {
            let [地址, 端口] = 解析地址端口字符串(proxyIP);

            if (proxyIP.includes('.tp')) {
                const tpMatch = proxyIP.match(/\.tp(\d+)/);
                if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
            }

            const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
            const ipv6Regex = /^\[?([a-fA-F0-9:]+)\]?$/;

            if (!ipv4Regex.test(地址) && !ipv6Regex.test(地址)) {
                let [aRecords, aaaaRecords] = await Promise.all([
                    DoH查询(地址, 'A'),
                    DoH查询(地址, 'AAAA')
                ]);

                let ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
                let ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
                let ipAddresses = [...ipv4List, ...ipv6List];

                if (ipAddresses.length === 0) {
                    console.log(`[反代解析] 默认DoH未获取到解析结果，切换Google DoH重试 ${地址}`);
                    [aRecords, aaaaRecords] = await Promise.all([
                        DoH查询(地址, 'A', 'https://dns.google/dns-query'),
                        DoH查询(地址, 'AAAA', 'https://dns.google/dns-query')
                    ]);
                    ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
                    ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
                    ipAddresses = [...ipv4List, ...ipv6List];
                }

                所有反代数组 = ipAddresses.length > 0
                    ? ipAddresses.map(ip => [ip, 端口])
                    : [[地址, 端口]];
            } else {
                所有反代数组 = [[地址, 端口]];
            }
        }
        const 排序后数组 = 所有反代数组.sort((a, b) => a[0].localeCompare(b[0]));
        const 目标根域名 = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
        let 随机种子 = [...(目标根域名 + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
        console.log(`[反代解析] 随机种子: ${随机种子}\n目标站点: ${目标根域名}`)
        const 洗牌后 = [...排序后数组].sort(() => (随机种子 = (随机种子 * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
        缓存反代解析数组 = 洗牌后.slice(0, 8);
        console.log(`[反代解析] 解析完成 总数: ${缓存反代解析数组.length}个\n${缓存反代解析数组.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
        缓存反代IP = proxyIP;
    } else console.log(`[反代解析] 读取缓存 总数: ${缓存反代解析数组.length}个\n${缓存反代解析数组.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
    return 缓存反代解析数组;
}

async function SOCKS5可用性验证(代理协议 = 'socks5', 代理参数) {
    const startTime = Date.now();
    try { parsedSocks5Address = await 获取SOCKS5账号(代理参数); } catch (err) { return { success: false, error: err.message, proxy: 代理协议 + "://" + 代理参数, responseTime: Date.now() - startTime }; }
    const { username, password, hostname, port } = parsedSocks5Address;
    const 完整代理参数 = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
    try {
        const initialData = new Uint8Array(0);
        const tcpSocket = 代理协议 == 'socks5' ? await socks5Connect('check.socks5.090227.xyz', 80, initialData) : await httpConnect('check.socks5.090227.xyz', 80, initialData);
        if (!tcpSocket) return { success: false, error: '无法连接到代理服务器', proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime };
        try {
            const writer = tcpSocket.writable.getWriter(), encoder = new TextEncoder();
            await writer.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: check.socks5.090227.xyz\r\nConnection: close\r\n\r\n`));
            writer.releaseLock();
            const reader = tcpSocket.readable.getReader(), decoder = new TextDecoder();
            let response = '';
            try { while (true) { const { done, value } = await reader.read(); if (done) break; response += decoder.decode(value, { stream: true }); } } finally { reader.releaseLock(); }
            await tcpSocket.close();
            return { success: true, proxy: 代理协议 + "://" + 完整代理参数, ip: response.match(/ip=(.*)/)[1], loc: response.match(/loc=(.*)/)[1], responseTime: Date.now() - startTime };
        } catch (error) {
            try { await tcpSocket.close(); } catch (e) { console.log('关闭连接时出错:', e); }
            return { success: false, error: error.message, proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime };
        }
    } catch (error) { return { success: false, error: error.message, proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime }; }
}

async function nginx() {
    return `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
}

async function html1101(host, 访问IP) {
    const now = new Date();
    const 格式化时间戳 = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0') + ' ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
    const 随机字符串 = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');

    return `<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
<head>
<title>Worker threw exception | ${host} | Cloudflare</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0}</style>


<!--[if gte IE 10]><!-->
<script>
  if (!navigator.cookieEnabled) {
    window.addEventListener('DOMContentLoaded', function () {
      var cookieEl = document.getElementById('cookie-alert');
      cookieEl.style.display = 'block';
    })
  }
</script>
<!--<![endif]-->

</head>
<body>
    <div id="cf-wrapper">
        <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">Please enable cookies.</div>
        <div id="cf-error-details" class="cf-error-details-wrapper">
            <div class="cf-wrapper cf-header cf-error-overview">
                <h1>
                    <span class="cf-error-type" data-translate="error">Error</span>
                    <span class="cf-error-code">1101</span>
                    <small class="heading-ray-id">Ray ID: ${随机字符串} &bull; ${格式化时间戳} UTC</small>
                </h1>
                <h2 class="cf-subheadline" data-translate="error_desc">Worker threw exception</h2>
            </div><!-- /.header -->
    
            <section></section><!-- spacer -->
    
            <div class="cf-section cf-wrapper">
                <div class="cf-columns two">
                    <div class="cf-column">
                        <h2 data-translate="what_happened">What happened?</h2>
                            <p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>
                    
                    <div class="cf-column">
                        <h2 data-translate="what_can_i_do">What can I do?</h2>
                            <p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${host}.</p>
                    </div>
                    
                </div>
            </div><!-- /.section -->
    
            <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">
    <p class="text-13">
      <span class="cf-footer-item sm:block sm:mb-1">Cloudflare Ray ID: <strong class="font-semibold"> ${随机字符串}</strong></span>
      <span class="cf-footer-separator sm:hidden">&bull;</span>
      <span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">
        Your IP:
        <button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button>
        <span class="hidden" id="cf-footer-ip">${访问IP}</span>
        <span class="cf-footer-separator sm:hidden">&bull;</span>
      </span>
      <span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; security by</span> <a rel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span>
      
    </p>
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->

        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->

     <script>
    window._cf_translation = {};
    
    
  </script> 
</body>
</html>`;
}


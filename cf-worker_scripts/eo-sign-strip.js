/**
 * 腾讯云 EdgeOne 边缘函数：出去盖证据，回来摘指纹（部署时整份粘贴，无外部依赖）。
 *
 * 一个请求只触发一条规则的函数（序号最小的那条），所以签名与摘头必须住同一份文件，
 * 否则总有一件事不会发生。因此这里只有一次 fetch：
 *   请求侧  写 X-CDN-Client-IP / X-CDN-Timestamp / X-CDN-Signature（HMAC-SHA256）
 *   响应侧  删 cf-* / server / via / alt-svc / x-amz-* 等对客户端与校验无实际作用的头
 *
 * 下层坏掉不许拦请求：签名不成退回未签名透传，摘头失败留着指纹出流量，只有回源本身
 * 失败才给 502。签名三件套是一个整体，缺一个就是错证据，所以异常时全部清掉。
 *
 * 签名消息串与源站逐字节一致：v1|<METHOD>|<clientIP>|<timestamp>。只绑方法，不绑主机
 * 与路径——回源 Host 与 URI 都可能被改写，绑了就是两边对不上，且这种不一致没有任何
 * 报错，只会让主人自己登不进去。
 *
 * 匹配全部是字符串操作（startsWith / 全等），不用正则：这一层没有锚点扩散、没有引擎
 * 差异，判定可逐条读懂；具名头直接 delete，不先 has（delete 缺省即 no-op，省一半原生
 * 调用）。不动 body / 状态码 / content-length / content-encoding：响应体一字未改，长度
 * 仍成立。3xx 用 redirect:'manual' 原样下发，源站 Location 与 Set-Cookie 不被运行时吃
 * 掉，也避免把旧签名带去跳转后的新 URL。
 */

'use strict';

/* ── 常量：响应侧删除名单 ───────────────────────────────────────── */

// 具名头：不依赖运行时能否枚举，残缺实现也删得干净；cf-ray 等按抓包实况列上
const DROP_EXACT = [
  // 服务器 / 代理 / 框架身份
  'server',
  'via',
  'x-powered-by',
  'x-backend-server',
  'x-hostname',
  'x-instance-id',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
  'x-drupal-cache',
  'x-runtime',
  // 诊断与上报
  'server-timing',
  'report-to',
  'nel',
  'reporting-endpoints',
  'network-error-logging',
  'expect-ct',
  // 能力声明
  'alt-svc',
  'alt-used',
  // Cloudflare 具名头（前缀规则再兜一层）
  'cf-ray',
  'cf-cache-status',
  'cf-placement',
  'cf-request-id',
  'cf-ipcountry',
  'cf-mitigated',
  'cf-chl-bypass',
  'cf-bgj',
  'cf-polished',
  'cf-worker',
  'cf-connecting-ip',
  'cf-connecting-ipv6',
  'x-cf-ray',
  'x-amz-cf-id',
  'x-amz-cf-pop',
  // 其他边缘指纹
  'x-cache',
  'x-cache-hits',
  'x-cache-status',
  'x-cacheable',
  'x-served-by',
  'x-turbo-charged-by',
  'x-varnish',
  'x-fastly-request-id',
  'x-fastly-ssl',
  'x-akamai-request-id',
  'x-akamai-session-info',
  'x-akamai-transformed',
  'x-azure-ref',
  'x-msedge-ref',
  'x-proxy-cache',
  'x-proxy-id',
  'x-edge-location',
  'x-litespeed-cache',
  // S3 / COS 源站元数据：前缀已能覆盖，这里逐个列名是第二道网——前缀层曾因运行时
  // keys()/forEach 与文档不符而整段失效过一次，那次这几个头全漏到了客户端。
  'x-amz-id-2',
  'x-amz-request-id',
  'x-amz-server-side-encryption',
  'x-amz-version-id',
  'x-amz-delete-marker',
  'x-amz-expiration',
  'x-amz-restore',
  'x-amz-storage-class',
  'x-amz-replication-status',
  'x-amz-tagging-count',
  'x-amz-website-redirect-location',
  'x-amz-object-lock-mode',
  'x-amz-object-lock-retain-until-date',
  'x-amz-object-lock-legal-hold',
  'x-amz-server-side-encryption-aws-kms-key-id',
  'x-amz-server-side-encryption-bucket-key-enabled',
  'x-amz-server-side-encryption-context',
  'x-amz-server-side-encryption-customer-algorithm',
  'x-amz-server-side-encryption-customer-key-md5',
  'x-amz-request-charged',
  'x-amz-archive-status',
  'x-amz-bucket-region',
  'x-amz-missing-meta',
  'x-amz-abort-date',
  'x-amz-abort-rule-id',
  // Firefox 自己写进 header dump 的，不是服务端头
  'x-firefox-spdy',
];

// 前缀：同族以后新加的头不至于漏出去
const DROP_PREFIX = [
  'cf-',
  'x-cf-',
  'x-cloudflare-',
  'cf_',
  'akamai-',
  'x-akamai-',
  'x-fastly-',
  'x-amz-',
  'x-cos-',
  'x-oss-',
  'x-goog-',
  'x-guploader-',
];

// 前缀删除的例外：校验与完整性头动了会毁签名/校验，必须留。
// 定长名字必须走全等，写成前缀会把 x-goog-hashx 这类一起放过。
// cos/oss 的 crc64 同属校验值：前缀层一旦工作，x-cos- / x-oss- 就会把它们删掉。
const KEEP_EXACT = [
  'x-amz-mp-parts-count',
  'x-cos-hash-crc64ecma',
  'x-oss-hash-crc64ecma',
  'x-goog-hash',
  'content-md5',
  'digest',
  'content-digest',
];
const KEEP_PREFIX = ['x-amz-checksum-'];

// CF 下发的 Cookie：浏览器从没和 CF 说过话，留着既是明文指纹又无作用。
// 名字取第一个 '=' 之前的部分（值里可能还有 '='）。
const CF_COOKIE_EXACT = ['cf_clearance'];
const CF_COOKIE_PREFIX = ['__cf', '_cf', 'cf_chl', 'cf_ob_', 'cf_use_ob', 'cf_use_ro'];

// Headers 写入上限（值 ≤ 4095 字节），超限 append 会抛
const HEADER_VALUE_MAX = 4095;

/* ── 常量：回源签名 ─────────────────────────────────────────────── */

const SECRET_ENV = 'SECRET-KEY';
const VERSION = 'v1';
const IP_HEADER = 'X-CDN-Client-IP';
const TIMESTAMP_HEADER = 'X-CDN-Timestamp';
const SIGNATURE_HEADER = 'X-CDN-Signature';

// keyPromise 让密钥只导入一次。每个请求都 importKey 是白花的 CPU，而这个函数在每次
// 回源时都要跑一遍。换密钥等于重新部署，隔离实例跟着换新。
let keyPromise = null;

/* ── 入口 ───────────────────────────────────────────────────────── */

addEventListener('fetch', function (event) {
  // 运行时若有此接口：本函数抛异常时退回默认回源，不把整站打成错误页
  if (typeof event.passThroughOnException === 'function') event.passThroughOnException();
  event.respondWith(handle(event));
});

/* ── 主流程 ─────────────────────────────────────────────────────── */

// 出去盖章、回来摘头，全程只一次 fetch。整段包在 try 里的理由：连 env 没配都算「签名
// 这一层坏了」，它不该让整站打不开。
async function handle(event) {
  const request = event.request;

  try {
    const secret = env[SECRET_ENV];
    const clientIP = (request.eo && request.eo.clientIp) || '';
    // 缺密钥就签不出东西，缺地址就没什么可签：两种都按未签名透传。
    if (secret && clientIP) {
      // 毫秒时间戳，与源站解析口径一致；它同时是签名能重放的窗口。
      const stamp = String(Date.now());
      const message = `${VERSION}|${request.method}|${clientIP}|${stamp}`;
      const signature = await sign(secret, message);
      if (signature) {
        request.headers.set(IP_HEADER, clientIP);
        request.headers.set(TIMESTAMP_HEADER, stamp);
        request.headers.set(SIGNATURE_HEADER, signature);
      }
    }
  } catch (err) {
    // 三个头是一个整体，缺一个就是错证据：宁可全部清掉，让源站按「没有证据」处理
    request.headers.delete(IP_HEADER);
    request.headers.delete(TIMESTAMP_HEADER);
    request.headers.delete(SIGNATURE_HEADER);
  }

  let response;
  try {
    // readTimeout 默认只有 15s，SSE / 长轮询会被掐断，这里按上限 300s 设
    response = await fetch(request, {
      redirect: 'manual',
      eo: {
        timeoutSetting: {
          connectTimeout: 3000,
          readTimeout: 300000,
          writeTimeout: 300000,
        },
      },
    });
  } catch (err) {
    return new Response('Bad Gateway', {
      status: 502,
      headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
    });
  }

  try {
    stripHeaders(response.headers);
  } catch (err) {
    /* 摘头失败不影响出流量：宁可留一条指纹，不把页面弄挂 */
  }
  return response;
}

/* ── 摘头 ───────────────────────────────────────────────────────── */

function stripHeaders(headers) {
  // 1. 具名头：直接删，不先 has
  for (let i = 0; i < DROP_EXACT.length; i++) headers.delete(DROP_EXACT[i]);

  // 2. 前缀兜底：枚举一次现有头名
  const names = listHeaderNames(headers);
  for (let i = 0; i < names.length; i++) {
    const name = names[i].toLowerCase(); // 已是小写时 V8 直接返回原串，不分配
    if (isChecksum(name)) continue;
    if (hasDropPrefix(name)) headers.delete(name);
  }

  // 3. Cookie
  stripCfCookies(headers);
}

function isChecksum(name) {
  for (let i = 0; i < KEEP_EXACT.length; i++) {
    if (name === KEEP_EXACT[i]) return true;
  }
  for (let i = 0; i < KEEP_PREFIX.length; i++) {
    if (name.startsWith(KEEP_PREFIX[i])) return true;
  }
  return false;
}

function hasDropPrefix(name) {
  for (let i = 0; i < DROP_PREFIX.length; i++) {
    if (name.startsWith(DROP_PREFIX[i])) return true;
  }
  return false;
}

function stripCfCookies(headers) {
  if (typeof headers.getSetCookie !== 'function') return;
  const lines = headers.getSetCookie();
  if (!lines || !lines.length) return;

  const kept = [];
  for (let i = 0; i < lines.length; i++) {
    if (!isCfCookie(lines[i])) kept.push(lines[i]);
  }
  if (kept.length === lines.length) return; // 没有 CF Cookie，整组不碰

  if (!kept.length) {
    headers.delete('set-cookie');
    return;
  }

  // 值上限按字节算，超了就直接放弃改写：宁可留几个 CF Cookie，也不把平台拒写的值硬塞
  for (let i = 0; i < kept.length; i++) {
    if (headerValueBytes(kept[i]) > HEADER_VALUE_MAX) return;
  }

  // 先在旁边试写一遍，确认平台肯收，再动真身。
  // 反过来做（先删后写、失败再恢复）会在恢复也被拒时把业务 Cookie 一起弄丢。
  if (!canWriteCookies(kept)) return;

  headers.delete('set-cookie');
  try {
    for (let i = 0; i < kept.length; i++) headers.append('set-cookie', kept[i]);
  } catch (err) {
    // 走到这儿已经是极小概率：清掉残值再整组恢复，不留重复 Set-Cookie
    headers.delete('set-cookie');
    for (let i = 0; i < lines.length; i++) headers.append('set-cookie', lines[i]);
  }
}

function canWriteCookies(lines) {
  let probe;
  try {
    probe = new Headers();
  } catch (err) {
    return true; // 没有可用的 Headers 构造器，交给真身自己抛
  }
  try {
    for (let i = 0; i < lines.length; i++) probe.append('set-cookie', lines[i]);
    return true;
  } catch (err) {
    return false;
  }
}

function isCfCookie(line) {
  const eq = line.indexOf('=');
  if (eq < 0) return false;

  let name = line.slice(0, eq);
  let start = 0;
  while (start < name.length && (name[start] === ' ' || name[start] === '\t')) start++;
  if (start) name = name.slice(start);
  name = name.toLowerCase();

  for (let i = 0; i < CF_COOKIE_EXACT.length; i++) {
    if (name === CF_COOKIE_EXACT[i]) return true;
  }
  for (let i = 0; i < CF_COOKIE_PREFIX.length; i++) {
    if (name.startsWith(CF_COOKIE_PREFIX[i])) return true;
  }
  return false;
}

/* ── 签名 ───────────────────────────────────────────────────────── */

function uint8ArrayToHex(uint8Array) {
  return Array.prototype.map
    .call(uint8Array, (x) => ('0' + x.toString(16)).slice(-2))
    .join('');
}

// signingKey 导入密钥；失败就缓存成 null，让后面每个请求都走未签名透传，而不是每个
// 请求都再失败一次。
function signingKey(secret) {
  if (!keyPromise) {
    keyPromise = crypto.subtle
      .importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      )
      .catch(() => null);
  }
  return keyPromise;
}

async function sign(secret, message) {
  const key = await signingKey(secret);
  if (!key) return '';
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return uint8ArrayToHex(new Uint8Array(mac));
}

/* ── 工具 ───────────────────────────────────────────────────────── */

// UTF-8 字节数：平台上限按字节算，非 ASCII 的 Cookie 值不能按 length 判
function headerValueBytes(value) {
  let bytes = 0;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x80) bytes += 1;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff) {
      bytes += 4; // 代理对，连同下一个码元共 4 字节
      i++;
    } else bytes += 3;
  }
  return bytes;
}

// 实测装配（2026-11-27，探针 eo-probe-headers.js 跑在线上）：
//   keys()    返回头名数组，没有 .next——盯着 next 判断会把唯一正确的那条路挡掉；
//   forEach   回调是 (value, name)，文档写的 (name, value) 与事实相反。
// 两条都按文档写，前缀层就整段空转：names 里全是「值」，一个前缀也匹配不上，
// 而且不抛异常，静默漏头。这里三条路都按实测接线，谁先可用就用谁。
function listHeaderNames(headers) {
  const names = [];

  if (typeof headers.keys === 'function') {
    try {
      const keys = headers.keys();
      if (Array.isArray(keys)) {
        for (let i = 0; i < keys.length; i++) names.push(String(keys[i]));
        return names;
      }
      if (keys && typeof keys.next === 'function') {
        for (let step = keys.next(); !step.done; step = keys.next()) {
          names.push(String(step.value));
        }
        return names;
      }
    } catch (err) {
      /* 退回 forEach */
    }
  }

  if (typeof headers.forEach === 'function') {
    headers.forEach(function (value, name) {
      names.push(String(name));
    });
  }
  return names;
}

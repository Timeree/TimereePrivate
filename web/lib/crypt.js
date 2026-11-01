/*
 * crypt.js —— 7z 加解密核心(加解密逻辑集中在这一个文件里)
 *
 * 浏览器与 Node 共用同一份代码,零 npm 依赖,底层都是随项目分发的
 * 7-Zip 24.09 WebAssembly 内核(lib/7zz.umd.js):
 *
 *   encrypt({ password, entries })  文件 → 7z(带密码,文件头一并加密)
 *   extract({ bytes, password })    7z  → 文件列表(密码错/损坏会抛错)
 *   headerEncrypted({ bytes })      文件头是否加密(用于打包自检)
 *   zip(entries, root)              文件列表 → 标准 ZIP(存储式,无第三方库)
 *   isSevenZip(bytes)               是否是 7z 文件
 *   crc32(bytes) / SEVEN_ZIP_MAGIC
 *
 * 浏览器:先加载 lib/7zz.umd.js(提供 window.SevenZip),
 *         需要 file:// 直开时再加载 lib/7zz.wasm.b64.js(提供内嵌载荷)。
 * Node:   require('./lib/crypt.js') 即可,wasm 从同目录读取。
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports && typeof require === 'function') {
    module.exports = factory(require, __dirname);
  } else {
    root.SevenCrypt = factory(null, null);
  }
})(typeof self !== 'undefined' ? self : this, function (nodeRequire, libDir) {
  'use strict';

  // 7z 文件头魔数:37 7A BC AF 27 1C
  var SEVEN_ZIP_MAGIC = new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
  // 自检用的探针密码:绝不可能等于真实密码。
  // 「不带正确密码也能列出文件名」就说明文件头没加密。
  var HEADER_PROBE = '__header_probe_7z__';

  var kernelPromise = null;   // 7-Zip 内核只初始化一次
  var zlog = [];              // 内核输出(含报错),失败时用来给用户看原因

  function fail(code, message) {
    var err = new Error(message);
    err.code = code;
    return err;
  }

  function isSevenZip(bytes) {
    if (!bytes || bytes.length < SEVEN_ZIP_MAGIC.length) return false;
    for (var i = 0; i < SEVEN_ZIP_MAGIC.length; i++) {
      if (bytes[i] !== SEVEN_ZIP_MAGIC[i]) return false;
    }
    return true;
  }

  function b64ToBytes(b64) {
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ---------------------------------------------------------------- 内核
  async function kernel() {
    if (kernelPromise) return kernelPromise;
    kernelPromise = (async function () {
      var opts = {
        print: function (t) { zlog.push(t); },
        printErr: function (t) { zlog.push(t); }
      };
      var factory;
      if (nodeRequire) {
        // Node:直接 require 同目录下的内核,wasm 也从同目录读
        factory = nodeRequire(libDir.replace(/\\/g, '/') + '/7zz.umd.js');
        opts.locateFile = function (name) { return require('path').join(libDir, name); };
      } else {
        if (typeof window === 'undefined' || typeof window.SevenZip !== 'function') {
          throw fail('KERNEL', '缺少 lib/7zz.umd.js(7-Zip 内核脚本)');
        }
        factory = window.SevenZip;
        if (typeof window.SEVENZIP_WASM_B64 === 'string') {
          // file:// 直开时无法用 fetch 取 .wasm,改用内嵌载荷(首次使用才解码)
          opts.wasmBinary = b64ToBytes(window.SEVENZIP_WASM_B64);
        } else {
          opts.locateFile = function (name) { return 'lib/' + name; };
        }
      }
      return await factory(opts);
    })();
    return kernelPromise;
  }

  // --------------------------------------------------------- 虚拟文件系统
  function rmTree(sz, dir) {
    var names;
    try { names = sz.FS.readdir(dir); } catch (e) { return; }
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      if (name === '.' || name === '..') continue;
      var p = dir + '/' + name;
      try {
        if (sz.FS.isDir(sz.FS.stat(p).mode)) rmTree(sz, p);
        else sz.FS.unlink(p);
      } catch (e) { /* 已不存在则忽略 */ }
    }
    try { sz.FS.rmdir(dir); } catch (e) { /* 同上 */ }
  }

  function mkdirp(sz, dir) {
    var parts = dir.replace(/^\/+/, '').split('/').filter(Boolean);
    var cur = '';
    for (var i = 0; i < parts.length; i++) {
      cur += '/' + parts[i];
      try { sz.FS.mkdir(cur); } catch (e) { /* 已存在 */ }
    }
  }

  // 调用 7z 并统一退出结果:0 成功;非 0(可能以「抛出数字」的形式)归一成返回值
  function run(sz, args) {
    zlog.length = 0;
    try {
      return sz.callMain(args);
    } catch (e) {
      if (typeof e === 'number') return e;
      throw e;  // 真正的内核异常继续往上抛
    }
  }

  function zlogText() { return zlog.join('\n'); }

  // -------------------------------------------------------------- 加密
  /**
   * 把 entries 打包成「文件头也加密」的 7z。
   * entries: [{ arcname, data?: Uint8Array, srcPath?: string }]
   *   srcPath 仅 Node 可用(直接从磁盘读),data 是浏览器用的内存字节。
   * 返回 Promise<Uint8Array>
   */
  async function encrypt(opts) {
    var password = opts && opts.password;
    var entries = (opts && opts.entries) || [];
    if (typeof password !== 'string' || password === '') {
      throw fail('ARGS', '密码不能为空');
    }
    if (!entries.length) throw fail('ARGS', '没有要打包的内容');

    var sz = await kernel();
    rmTree(sz, '/stg');
    mkdirp(sz, '/stg');
    sz.FS.chdir('/stg');

    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i];
      var arc = String(entry.arcname || '').replace(/^\/+/, '');
      if (!arc || arc.split('/').some(function (s) { return s === '..' || s === ''; })) {
        throw fail('ARGS', '非法的包内路径: ' + entry.arcname);
      }
      var target = '/stg/' + arc;
      if (entry.isDir) {
        mkdirp(sz, target);
        continue;
      }
      var data = entry.data;
      if (!data && entry.srcPath) data = nodeRequire('fs').readFileSync(entry.srcPath);
      if (!data) throw fail('IO', '读不到: ' + entry.arcname);
      mkdirp(sz, target.replace(/\/[^/]+$/, ''));
      var st = sz.FS.open(target, 'w');
      sz.FS.write(st, data, 0, data.length);
      sz.FS.close(st);
    }

    // 输出放到暂存区之外,免得把结果自己压进去;
    // -mhe=on 加密文件头(文件名/目录结构),-mx=5 标准压缩率
    try { sz.FS.unlink('/out.7z'); } catch (e) { /* 可能不存在 */ }
    var rc = run(sz, ['a', '-t7z', '-p' + password, '-mhe=on', '-mx=5',
                      '-y', '-bso0', '-bsp0', '/out.7z', '*']);
    if (rc !== 0) throw fail('PACK', '7z 打包失败(exit ' + rc + ')' + tail(zlogText()));

    var bytes = sz.FS.readFile('/out.7z');
    rmTree(sz, '/stg');
    return bytes;
  }

  function tail(text) {
    var lines = (text || '').split('\n').filter(function (l) { return l.trim(); });
    return lines.length ? ': ' + lines.slice(-3).join('; ') : '';
  }

  // -------------------------------------------------------------- 解密
  /**
   * 解密 7z,返回包内条目。
   * entries: [{ dir }] 或 [{ path, data }] —— 与打包时同形,可直接喂给 zip()。
   * 密码错/文件损坏:reject,code = 'FAILED';没有内容:code = 'EMPTY'。
   */
  async function extract(opts) {
    var password = opts && opts.password;
    var bytes = opts && opts.bytes;
    if (typeof password !== 'string' || password === '') {
      throw fail('ARGS', '密码不能为空');
    }
    if (!isSevenZip(bytes)) throw fail('ARGS', '不是有效的 7z 文件');

    var sz = await kernel();
    rmTree(sz, '/in.7z');
    rmTree(sz, '/out');

    var st = sz.FS.open('/in.7z', 'w');
    sz.FS.write(st, bytes, 0, bytes.length);
    sz.FS.close(st);
    sz.FS.mkdir('/out');

    var rc = run(sz, ['x', '-p' + password, '-y', '-bso0', '-bsp0', '-o/out', '/in.7z']);
    if (rc !== 0) {
      var log = zlogText();
      throw fail('FAILED', /password|密码/i.test(log)
        ? '解密失败:密码不正确。'
        : '解密失败:密码不正确,或压缩包已损坏。');
    }

    var entries = [];
    (function walk(dir, rel) {
      var names = sz.FS.readdir(dir);
      for (var i = 0; i < names.length; i++) {
        var name = names[i];
        if (name === '.' || name === '..') continue;
        var p = dir + '/' + name;
        var st2 = sz.FS.stat(p);
        var r = rel ? rel + '/' + name : name;
        if (sz.FS.isDir(st2.mode)) {
          entries.push({ dir: r });
          walk(p, r);
        } else {
          entries.push({ path: r, data: sz.FS.readFile(p) });
        }
      }
    })('/out', '');

    if (!entries.length) throw fail('EMPTY', '没有解出任何内容,可能密码不正确。');
    rmTree(sz, '/in.7z');
    rmTree(sz, '/out');
    return { entries: entries, fileCount: entries.filter(function (e) { return !e.dir; }).length };
  }

  /**
   * 文件头是否加密:拿一个「肯定不对」的密码去列目录。
   * 列得出来 → 文件名是明文(没加密);列不出来 → 文件头已加密。
   * 打包自检用:7z 内核哪天忽略 -mhe=on 时这里能立刻发现。
   */
  async function headerEncrypted(opts) {
    var bytes = opts && opts.bytes;
    if (!isSevenZip(bytes)) throw fail('ARGS', '不是有效的 7z 文件');
    var sz = await kernel();
    rmTree(sz, '/probe.7z');
    var st = sz.FS.open('/probe.7z', 'w');
    sz.FS.write(st, bytes, 0, bytes.length);
    sz.FS.close(st);
    var rc = run(sz, ['l', '-bso0', '-bsp0', '-p' + HEADER_PROBE, '/probe.7z']);
    rmTree(sz, '/probe.7z');
    return rc !== 0;  // 能列出(0)= 文件头是明文
  }

  // ------------------------------------------------------ ZIP(存储式)
  var CRC_TABLE = (function () {
    var table = new Uint32Array(256);
    for (var n = 0; n < 256; n++) {
      var c = n;
      for (var k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      table[n] = c >>> 0;
    }
    return table;
  })();

  function crc32(buf) {
    var c = 0xffffffff;
    for (var i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }

  function dosDateTime(d) {
    var year = Math.min(2107, Math.max(1980, d.getFullYear()));
    return {
      time: ((d.getHours() & 31) << 11) | ((d.getMinutes() & 63) << 5) | ((d.getSeconds() / 2) & 31),
      date: ((year - 1980) << 9) | (((d.getMonth() + 1) & 15) << 5) | (d.getDate() & 31)
    };
  }

  // 传统 ZIP(无 zip64)的硬上限;超出就别硬拼一个解不开的包
  var ZIP_MAX_ENTRIES = 0xffff;
  var ZIP_MAX_BYTES = 0xffffffff;

  /**
   * 把 entries 打成标准 ZIP(仅存储 + CRC32),返回 Uint8Array。
   * 所有内容收进 rootName 这一个根文件夹:解压得到一个目录,而不是散落一地。
   *   不压:7z 那边已经压过,再压既慢又没意义;
   *   手写:解密后立刻可得精确字节数,且不引入任何第三方库。
   */
  function zip(entries, rootName) {
    var enc = new TextEncoder();
    var stamp = dosDateTime(new Date());
    var parts = [], central = [];
    var offset = 0, fileCount = 0;
    var root = String(rootName || 'decrypted').replace(/[\\/:*?"<>|#]+/g, '_').replace(/^\.+$/, '');
    if (!root) root = 'decrypted';

    if (entries.length > ZIP_MAX_ENTRIES) {
      throw fail('ZIP', '文件太多(' + entries.length + ' 个),超过 ZIP 上限 ' + ZIP_MAX_ENTRIES);
    }

    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i];
      var isDir = !!entry.dir;
      var rel = root + '/' + (isDir ? entry.dir : entry.path);
      var nameBytes = enc.encode(isDir ? rel + '/' : rel);
      var data = isDir ? new Uint8Array(0) : entry.data;
      var crc = crc32(data);
      var flags = 0x0800 | (isDir ? 0x10 : 0x0000);  // 0x0800 = 文件名用 UTF-8

      if (data.length > ZIP_MAX_BYTES) {
        throw fail('ZIP', '文件过大,超过 ZIP 上限 4GB:' + rel);
      }
      var projected = offset + 30 + nameBytes.length + data.length;
      if (projected > ZIP_MAX_BYTES) {
        throw fail('ZIP', '解密后体积超过 4GB,超出 ZIP(非 zip64)上限,无法打包下载。');
      }

      // ---- 本地文件头 ----
      var lh = new DataView(new ArrayBuffer(30));
      lh.setUint32(0, 0x04034b50, true);        // 签名
      lh.setUint16(4, 20, true);                // 版本需要 2.0
      lh.setUint16(6, flags, true);             // 标志
      lh.setUint16(8, 0, true);                 // 方法 0 = 仅存储
      lh.setUint16(10, stamp.time, true);
      lh.setUint16(12, stamp.date, true);
      lh.setUint32(14, crc, true);
      lh.setUint32(18, data.length, true);      // 压缩后大小
      lh.setUint32(22, data.length, true);      // 未压缩大小
      lh.setUint16(26, nameBytes.length, true); // 文件名长度
      lh.setUint16(28, 0, true);                // 附加域长度

      var localOffset = offset;
      var lhBytes = new Uint8Array(lh.buffer);
      parts.push(lhBytes, nameBytes);
      offset += lhBytes.length + nameBytes.length;
      if (!isDir) { parts.push(data); offset += data.length; fileCount++; }

      // ---- 中央目录条目(先暂存,稍后集中输出) ----
      var ch = new DataView(new ArrayBuffer(46));
      ch.setUint32(0, 0x02014b50, true);
      ch.setUint16(4, 20, true);               // 版本创建者
      ch.setUint16(6, 20, true);               // 版本需要
      ch.setUint16(8, flags, true);
      ch.setUint16(10, 0, true);               // 方法 0
      ch.setUint16(12, stamp.time, true);
      ch.setUint16(14, stamp.date, true);
      ch.setUint32(16, crc, true);
      ch.setUint32(20, data.length, true);
      ch.setUint32(24, data.length, true);
      ch.setUint16(28, nameBytes.length, true);
      ch.setUint16(30, 0, true);              // 附加域
      ch.setUint16(32, 0, true);              // 注释
      ch.setUint16(34, 0, true);              // 磁盘号
      ch.setUint16(36, 0, true);              // 内部属性
      ch.setUint32(38, isDir ? 0x10 : 0, true); // 外部属性
      ch.setUint32(42, localOffset, true);
      central.push(new Uint8Array(ch.buffer), nameBytes);
    }

    var centralOffset = offset;
    var centralSize = 0;
    for (var c = 0; c < central.length; c++) { centralSize += central[c].length; offset += central[c].length; }
    if (offset > ZIP_MAX_BYTES) {
      throw fail('ZIP', '解密后体积超过 4GB,超出 ZIP(非 zip64)上限,无法打包下载。');
    }
    parts.push.apply(parts, central);

    // ---- 中央目录结束记录 ----
    var eo = new DataView(new ArrayBuffer(22));
    eo.setUint32(0, 0x06054b50, true);
    eo.setUint16(4, 0, true);
    eo.setUint16(6, 0, true);
    eo.setUint16(8, entries.length, true);
    eo.setUint16(10, entries.length, true);
    eo.setUint32(12, centralSize, true);
    eo.setUint32(16, centralOffset, true);
    eo.setUint16(20, 0, true);
    parts.push(new Uint8Array(eo.buffer));

    var total = 0;
    for (var p = 0; p < parts.length; p++) total += parts[p].length;
    var out = new Uint8Array(total);
    var at = 0;
    for (var q = 0; q < parts.length; q++) { out.set(parts[q], at); at += parts[q].length; }
    return out;
  }

  return {
    SEVEN_ZIP_MAGIC: SEVEN_ZIP_MAGIC,
    isSevenZip: isSevenZip,
    encrypt: encrypt,
    extract: extract,
    headerEncrypted: headerEncrypted,
    zip: zip,
    crc32: crc32
  };
});

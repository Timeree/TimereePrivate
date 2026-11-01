#!/usr/bin/env node
/*
 * encryptor.js —— 目录打包 + 7z 加密工具(加密端,Node 版)
 *
 * 把「源目录」下的全部文件/子目录打包成一个 7z 压缩包,密码取自指定文本文件的
 * 全部内容,并且对文件头一并加密(header encryption):没有密码连文件名、目录
 * 结构都读不出来。生成后会自动解密回读自检一次,确保密码可用、数据完好。
 *
 * 加解密的核心逻辑都在 lib/crypt.js(与网页 index.html 共用同一份)。
 * 配套的 index.html 是解密端:放在压缩包同一目录,输入密码即可解密并下载。
 *
 * 用法:
 *   node encryptor.js --src ./素材 --out ./发布 --pw ./password.txt
 *
 * 依赖:仅 Node.js(无需 npm install,7z 内核已随项目放在 lib/ 里)
 */

'use strict';

const fs = require('fs');
const path = require('path');

const crypt = require(path.join(__dirname, 'lib', 'crypt.js'));

const MANIFEST_NAME = 'archive.json';
const MANIFEST_FORMAT = '7z-encrypted/1';
// 固定输出名:加密端只产出 blob.7z,解密页面也固定读这一个文件
const FIXED_ARCHIVE_NAME = 'blob.7z';

class EncryptorError extends Error {}

// ------------------------------------------------------------------ 小工具
function humanSize(num) {
  let size = Number(num) || 0;
  for (const unit of ['B', 'KB', 'MB', 'GB', 'TB']) {
    if (size < 1024 || unit === 'TB') return unit === 'B' ? `${size} ${unit}` : `${size.toFixed(1)} ${unit}`;
    size /= 1024;
  }
  return `${num} B`;
}

const isWithin = (p, parent) => p === parent || p.startsWith(parent + path.sep);

function unlinkQuiet(p) {
  try { fs.unlinkSync(p); } catch (e) { /* 已不存在则忽略 */ }
}

// ------------------------------------------------------------------ 密码
function readPassword(file) {
  if (!fs.existsSync(file)) throw new EncryptorError(`密码文件不存在: ${file}`);
  let raw;
  try { raw = fs.readFileSync(file); } catch (e) {
    throw new EncryptorError(`读不到密码文件 ${file}: ${e.message}`);
  }
  if (!raw.length) throw new EncryptorError(`密码文件是空的: ${file}`);

// utf-8-sig 等价:吃掉 Windows 记事本的 BOM 再按文本解码
  const text = raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf
    ? raw.subarray(3).toString('utf8')
    : raw.toString('utf8');
  if (text.includes('\0')) {
    throw new EncryptorError(`密码文件包含 \\x00 字符,无法作为密码使用: ${file}`);
  }

  const password = text.replace(/[\r\n]+$/, '');  // 只去掉结尾换行,编辑器保存文本时会带上
  if (!password) throw new EncryptorError(`密码文件去掉换行后是空的: ${file}`);
  if (/[\r\n]/.test(password)) {
    throw new EncryptorError(
      `密码文件含有多行内容(中间有换行)。解密页面只有一个输入框,` +
      `无法输入换行,请把密码写成单行: ${file}`
    );
  }
  return password;
}

// ------------------------------------------------------------ 收集待打包条目
function collectEntries(root, outdir, exclude) {
  const excluded = new Set(exclude);
  const outdirInsideSrc = outdir !== root && isWithin(outdir, root);
  const skip = (p) => excluded.has(p) || (outdirInsideSrc && isWithin(p, outdir));

  const entries = [];
  const warnings = [];
  const skippedLinks = [];

  const walk = (dir) => {
    const names = fs.readdirSync(dir, { withFileTypes: true })
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const subdirs = [];
    for (const d of names) {
      const full = path.join(dir, d.name);
      const rel = path.relative(root, full).split(path.sep).join('/');
      if (d.isSymbolicLink()) { skippedLinks.push(rel); continue; }
      if (skip(full)) continue;
      if (d.isDirectory()) { entries.push({ srcPath: full, arcname: rel, isDir: true }); subdirs.push(full); }
      else if (d.isFile()) entries.push({ srcPath: full, arcname: rel, isDir: false });
      else warnings.push(`跳过特殊文件(非普通文件): ${rel}`);
    }
    subdirs.forEach(walk);
  };
  walk(root);

  if (skippedLinks.length) {
    warnings.push(`跳过符号链接: ${skippedLinks.slice(0, 5).join('、')}` +
      (skippedLinks.length > 5 ? `(共 ${skippedLinks.length} 个)` : ''));
  }
  return { entries, warnings };
}

// ------------------------------------------------------------------ 文件名
// 输出名固定为 blob.7z:解密页面只认这一个文件,不允许改名
function archiveName() {
  return FIXED_ARCHIVE_NAME;
}

// ------------------------------------------------------------------ 清单
function writeManifest(file, outfile, mode) {
  const payload = {
    format: MANIFEST_FORMAT,
    archive: path.basename(outfile),
    size: fs.statSync(outfile).size
  };
  const tmp = `${file}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(payload, null, 2) + '\n');
    fs.chmodSync(tmp, mode);
    fs.renameSync(tmp, file);   // 原子替换:页面任何时刻读到的都是完整 JSON
  } catch (e) {
    unlinkQuiet(tmp);
    throw e;
  }
}

// ------------------------------------------------------------------ 自检
async function verify(bytes, password) {
  if (!crypt.isSevenZip(bytes)) throw new EncryptorError('生成的结果不是有效的 7z 文件');
  if (!(await crypt.headerEncrypted({ bytes }))) {
    throw new EncryptorError('生成的压缩包文件头没有加密,已放弃(请检查 7z 内核行为)');
  }
  try {
    // entries 里目录也算条目;只有「一个条目都没有」才是真空包
    const { entries } = await crypt.extract({ bytes, password });
    if (!entries.length) throw new Error('解出了 0 个条目');
  } catch (e) {
    throw new EncryptorError(`自检失败,无法用密码读回压缩包: ${e.message}`);
  }
}

// ------------------------------------------------------------------ 命令行
function parseArgs(argv) {
  const opts = { src: '.', force: false, verify: true, verbose: false, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = (flag) => {                       // 取值并让循环跳过该值
      const v = argv[++i];
      if (v == null || (v.startsWith('--') && v.length > 2)) {
        throw new EncryptorError(`${flag} 需要一个参数`);
      }
      return v;
    };
    if (a === '--src') opts.src = need(a);
    else if (a === '--out') opts.out = need(a);
    else if (a === '--pw') opts.pw = need(a);
    else if (a === '--name') {
      const v = need(a);
      throw new EncryptorError(`输出名固定为 ${FIXED_ARCHIVE_NAME},不能再改名(请去掉 --name ${v})`);
    }
    else if (a === '--force') opts.force = true;
    else if (a === '--no-verify') opts.verify = false;
    else if (a === '-v' || a === '--verbose') opts.verbose = true;
    else if (a === '-q' || a === '--quiet') opts.quiet = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else throw new EncryptorError(`不认识的参数: ${a}(用 --help 看用法)`);
  }
  return opts;
}

const HELP = `
encryptor.js —— 把源目录打包成带密码的 7z 压缩包,文件名等文件头信息一并加密。

用法:
  node encryptor.js --src <目录> --out <目录> --pw <密码文件> [选项]

选项:
  --src <目录>      要打包的源目录(默认:当前目录)
  --out <目录>      输出目录(不存在会自动创建)【必填】
  --pw <文件>       密码文件,文件里的全部内容即密码【必填】
  --force           覆盖已存在的 ${FIXED_ARCHIVE_NAME}
  --no-verify       跳过生成后的解密自检
  -v, --verbose     列出每一个被打包的条目
  -q, --quiet       只输出错误
  -h, --help        显示本帮助

示例:
  node encryptor.js --src ./素材 --out ./发布 --pw ./password.txt

输出固定为 ${FIXED_ARCHIVE_NAME}(名称不可改,解密页面只认它),
另有一份 ${MANIFEST_NAME} 清单记录压缩包名和大小。

打包完成后,把 index.html、lib/、${MANIFEST_NAME} 与 ${FIXED_ARCHIVE_NAME}
放进同一目录,即可在浏览器里输入密码解密并下载。`;

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`错误: ${e.message}\n`);
    return 1;
  }
  if (args.help) { console.log(HELP); return 0; }
  if (!args.out) { process.stderr.write('错误: 缺少 --out(输出目录)\n用 --help 看用法\n'); return 1; }
  if (!args.pw) { process.stderr.write('错误: 缺少 --pw(密码文件)\n用 --help 看用法\n'); return 1; }

  const say = args.quiet ? () => {} : (...a) => console.log(...a);

  try {
    // 1) 源目录
    let src = path.resolve(args.src);
    if (!fs.existsSync(src)) throw new EncryptorError(`源目录不存在: ${src}`);
    const srcStat = fs.statSync(src);
    if (srcStat.isFile()) {
      throw new EncryptorError(
        `--src 需要一个目录,而这是个文件: ${src}\n(要打包单个文件,请把它放进一个目录再指定该目录)`
      );
    }
    if (!srcStat.isDirectory()) throw new EncryptorError(`--src 不是一个目录: ${src}`);

    // 2) 输出位置与文件名
    const outdir = path.resolve(args.out);
    fs.mkdirSync(outdir, { recursive: true });
    const outfile = path.join(outdir, archiveName(args.name));

    // 3) 密码(整个文件内容即密码)
    const passwordFile = path.resolve(args.pw);
    const password = readPassword(passwordFile);

    if (fs.existsSync(outfile) && !args.force) {
      throw new EncryptorError(`输出文件已存在: ${outfile}\n(确认要覆盖请加 --force)`);
    }

    // 4) 收集条目:源目录里有什么打包什么(密码文件也不例外)。
    //    只排除我们自己要写的两个产物,免得把上一轮的 blob.7z 塞进新包里。
    const manifestFile = path.join(outdir, MANIFEST_NAME);
    const exclude = [outfile, manifestFile];
    const { entries, warnings } = collectEntries(src, outdir, exclude);
    if (!entries.length) throw new EncryptorError(`源目录里没有可打包的文件: ${src}`);

    warnings.forEach((w) => say(`警告: ${w}`));
    const nDirs = entries.filter((e) => e.isDir).length;
    const nFiles = entries.length - nDirs;
    if (args.verbose) {
      for (const e of entries) {
        const kind = e.isDir ? '目录' : '文件';
        const size = e.isDir ? '' : `  (${humanSize(fs.statSync(e.srcPath).size)})`;
        console.log(`  ${kind} ${e.arcname}${size}`);
      }
    }
    say(`源目录  : ${src}(${nFiles} 个文件,${nDirs} 个目录)`);
    say(`密码文件: ${passwordFile}(${[...password].length} 个字符)`);
    say(`正在打包: ${entries.length} 个条目 ...`);

    // 5) 打包(先写临时文件,校验通过才原子替换到目标位置)
    const tmp = `${outfile}.${process.pid}.${Date.now()}.tmp`;
    try {
      const bytes = await crypt.encrypt({ password, entries });
      fs.writeFileSync(tmp, bytes);
      let verifyDesc = '未自检(--no-verify)';
      if (args.verify) {
        await verify(bytes, password);
        verifyDesc = '自检通过:密码可解、内容完好、文件头已加密';
      }
      const umask = process.umask();      // 取出再放回,拿到进程当前 umask
      process.umask(umask);
      const mode = 0o666 & ~umask;
      fs.chmodSync(tmp, mode);
      fs.renameSync(tmp, outfile);

      const rawSize = entries.reduce((n, e) => n + (e.isDir ? 0 : fs.statSync(e.srcPath).size), 0);
      const outSize = fs.statSync(outfile).size;
      writeManifest(manifestFile, outfile, mode);

      say(`输出文件: ${outfile}(${humanSize(outSize)},原始数据 ${humanSize(rawSize)})`);
      say(`清单文件: ${manifestFile}(记录压缩包名与大小)`);
      say(`${verifyDesc};不输入密码看不到文件名`);
      say(`下一步: 把 index.html、lib/、${MANIFEST_NAME} 与这个 .7z 放进同一目录,即可在浏览器中解密下载。`);
      return 0;
    } catch (e) {
      unlinkQuiet(tmp);
      throw e;
    }
  } catch (e) {
    if (e instanceof EncryptorError) {
      process.stderr.write(`错误: ${e.message}\n`);
      return 1;
    }
    process.stderr.write(`错误: ${e && e.stack ? e.stack : e}\n`);
    return 1;
  }
}

main().then((code) => { process.exitCode = code; });

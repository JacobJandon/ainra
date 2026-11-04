(function(){ if (globalThis.Buffer) return;
  const dec = (s) => { s = s.replace(/[^A-Za-z0-9+/]/g, ""); while (s.length % 4) s += "="; const bin = atob(s);
    const u = new Uint8Array(bin.length); for (let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u; };
  const encB64 = (u) => { let s=""; for (let i=0;i<u.length;i++) s+=String.fromCharCode(u[i]); return btoa(s); };
  globalThis.Buffer = { from(x, enc){ let u;
    if (typeof x === "string") u = enc === "base64" ? dec(x) : new TextEncoder().encode(x);
    else u = x instanceof Uint8Array ? x : new Uint8Array(x);
    u.toString = (e) => e === "base64" ? encB64(u) : new TextDecoder().decode(u); return u; } };
})();
var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// node_modules/fflate/esm/browser.js
var u8 = Uint8Array;
var u16 = Uint16Array;
var i32 = Int32Array;
var fleb = new u8([
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  1,
  1,
  1,
  1,
  2,
  2,
  2,
  2,
  3,
  3,
  3,
  3,
  4,
  4,
  4,
  4,
  5,
  5,
  5,
  5,
  0,
  /* unused */
  0,
  0,
  /* impossible */
  0
]);
var fdeb = new u8([
  0,
  0,
  0,
  0,
  1,
  1,
  2,
  2,
  3,
  3,
  4,
  4,
  5,
  5,
  6,
  6,
  7,
  7,
  8,
  8,
  9,
  9,
  10,
  10,
  11,
  11,
  12,
  12,
  13,
  13,
  /* unused */
  0,
  0
]);
var clim = new u8([16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]);
var freb = function(eb, start) {
  var b = new u16(31);
  for (var i2 = 0; i2 < 31; ++i2) {
    b[i2] = start += 1 << eb[i2 - 1];
  }
  var r = new i32(b[30]);
  for (var i2 = 1; i2 < 30; ++i2) {
    for (var j = b[i2]; j < b[i2 + 1]; ++j) {
      r[j] = j - b[i2] << 5 | i2;
    }
  }
  return { b, r };
};
var _a = freb(fleb, 2);
var fl = _a.b;
var revfl = _a.r;
fl[28] = 258, revfl[258] = 28;
var _b = freb(fdeb, 0);
var fd = _b.b;
var revfd = _b.r;
var rev = new u16(32768);
for (i = 0; i < 32768; ++i) {
  x = (i & 43690) >> 1 | (i & 21845) << 1;
  x = (x & 52428) >> 2 | (x & 13107) << 2;
  x = (x & 61680) >> 4 | (x & 3855) << 4;
  rev[i] = ((x & 65280) >> 8 | (x & 255) << 8) >> 1;
}
var x;
var i;
var hMap = (function(cd, mb, r) {
  var s = cd.length;
  var i2 = 0;
  var l = new u16(mb);
  for (; i2 < s; ++i2) {
    if (cd[i2])
      ++l[cd[i2] - 1];
  }
  var le = new u16(mb);
  for (i2 = 1; i2 < mb; ++i2) {
    le[i2] = le[i2 - 1] + l[i2 - 1] << 1;
  }
  var co;
  if (r) {
    co = new u16(1 << mb);
    var rvb = 15 - mb;
    for (i2 = 0; i2 < s; ++i2) {
      if (cd[i2]) {
        var sv = i2 << 4 | cd[i2];
        var r_1 = mb - cd[i2];
        var v = le[cd[i2] - 1]++ << r_1;
        for (var m = v | (1 << r_1) - 1; v <= m; ++v) {
          co[rev[v] >> rvb] = sv;
        }
      }
    }
  } else {
    co = new u16(s);
    for (i2 = 0; i2 < s; ++i2) {
      if (cd[i2]) {
        co[i2] = rev[le[cd[i2] - 1]++] >> 15 - cd[i2];
      }
    }
  }
  return co;
});
var flt = new u8(288);
for (i = 0; i < 144; ++i)
  flt[i] = 8;
var i;
for (i = 144; i < 256; ++i)
  flt[i] = 9;
var i;
for (i = 256; i < 280; ++i)
  flt[i] = 7;
var i;
for (i = 280; i < 288; ++i)
  flt[i] = 8;
var i;
var fdt = new u8(32);
for (i = 0; i < 32; ++i)
  fdt[i] = 5;
var i;
var flrm = /* @__PURE__ */ hMap(flt, 9, 1);
var fdrm = /* @__PURE__ */ hMap(fdt, 5, 1);
var max = function(a) {
  var m = a[0];
  for (var i2 = 1; i2 < a.length; ++i2) {
    if (a[i2] > m)
      m = a[i2];
  }
  return m;
};
var bits = function(d, p, m) {
  var o = p / 8 | 0;
  return (d[o] | d[o + 1] << 8) >> (p & 7) & m;
};
var bits16 = function(d, p) {
  var o = p / 8 | 0;
  return (d[o] | d[o + 1] << 8 | d[o + 2] << 16) >> (p & 7);
};
var shft = function(p) {
  return (p + 7) / 8 | 0;
};
var slc = function(v, s, e) {
  if (s == null || s < 0)
    s = 0;
  if (e == null || e > v.length)
    e = v.length;
  return new u8(v.subarray(s, e));
};
var ec = [
  "unexpected EOF",
  "invalid block type",
  "invalid length/literal",
  "invalid distance",
  "stream finished",
  "no stream handler",
  ,
  "no callback",
  "invalid UTF-8 data",
  "extra field too long",
  "date not in range 1980-2099",
  "filename too long",
  "stream finishing",
  "invalid zip data"
  // determined by unknown compression method
];
var err = function(ind, msg, nt) {
  var e = new Error(msg || ec[ind]);
  e.code = ind;
  if (Error.captureStackTrace)
    Error.captureStackTrace(e, err);
  if (!nt)
    throw e;
  return e;
};
var inflt = function(dat, st, buf, dict) {
  var sl = dat.length, dl = dict ? dict.length : 0;
  if (!sl || st.f && !st.l)
    return buf || new u8(0);
  var noBuf = !buf;
  var resize = noBuf || st.i != 2;
  var noSt = st.i;
  if (noBuf)
    buf = new u8(sl * 3);
  var cbuf = function(l2) {
    var bl = buf.length;
    if (l2 > bl) {
      var nbuf = new u8(Math.max(bl * 2, l2));
      nbuf.set(buf);
      buf = nbuf;
    }
  };
  var final = st.f || 0, pos = st.p || 0, bt = st.b || 0, lm = st.l, dm = st.d, lbt = st.m, dbt = st.n;
  var tbts = sl * 8;
  do {
    if (!lm) {
      final = bits(dat, pos, 1);
      var type = bits(dat, pos + 1, 3);
      pos += 3;
      if (!type) {
        var s = shft(pos) + 4, l = dat[s - 4] | dat[s - 3] << 8, t = s + l;
        if (t > sl) {
          if (noSt)
            err(0);
          break;
        }
        if (resize)
          cbuf(bt + l);
        buf.set(dat.subarray(s, t), bt);
        st.b = bt += l, st.p = pos = t * 8, st.f = final;
        continue;
      } else if (type == 1)
        lm = flrm, dm = fdrm, lbt = 9, dbt = 5;
      else if (type == 2) {
        var hLit = bits(dat, pos, 31) + 257, hcLen = bits(dat, pos + 10, 15) + 4;
        var tl = hLit + bits(dat, pos + 5, 31) + 1;
        pos += 14;
        var ldt = new u8(tl);
        var clt = new u8(19);
        for (var i2 = 0; i2 < hcLen; ++i2) {
          clt[clim[i2]] = bits(dat, pos + i2 * 3, 7);
        }
        pos += hcLen * 3;
        var clb = max(clt), clbmsk = (1 << clb) - 1;
        var clm = hMap(clt, clb, 1);
        for (var i2 = 0; i2 < tl; ) {
          var r = clm[bits(dat, pos, clbmsk)];
          pos += r & 15;
          var s = r >> 4;
          if (s < 16) {
            ldt[i2++] = s;
          } else {
            var c = 0, n = 0;
            if (s == 16)
              n = 3 + bits(dat, pos, 3), pos += 2, c = ldt[i2 - 1];
            else if (s == 17)
              n = 3 + bits(dat, pos, 7), pos += 3;
            else if (s == 18)
              n = 11 + bits(dat, pos, 127), pos += 7;
            while (n--)
              ldt[i2++] = c;
          }
        }
        var lt = ldt.subarray(0, hLit), dt = ldt.subarray(hLit);
        lbt = max(lt);
        dbt = max(dt);
        lm = hMap(lt, lbt, 1);
        dm = hMap(dt, dbt, 1);
      } else
        err(1);
      if (pos > tbts) {
        if (noSt)
          err(0);
        break;
      }
    }
    if (resize)
      cbuf(bt + 131072);
    var lms = (1 << lbt) - 1, dms = (1 << dbt) - 1;
    var lpos = pos;
    for (; ; lpos = pos) {
      var c = lm[bits16(dat, pos) & lms], sym = c >> 4;
      pos += c & 15;
      if (pos > tbts) {
        if (noSt)
          err(0);
        break;
      }
      if (!c)
        err(2);
      if (sym < 256)
        buf[bt++] = sym;
      else if (sym == 256) {
        lpos = pos, lm = null;
        break;
      } else {
        var add3 = sym - 254;
        if (sym > 264) {
          var i2 = sym - 257, b = fleb[i2];
          add3 = bits(dat, pos, (1 << b) - 1) + fl[i2];
          pos += b;
        }
        var d = dm[bits16(dat, pos) & dms], dsym = d >> 4;
        if (!d)
          err(3);
        pos += d & 15;
        var dt = fd[dsym];
        if (dsym > 3) {
          var b = fdeb[dsym];
          dt += bits16(dat, pos) & (1 << b) - 1, pos += b;
        }
        if (pos > tbts) {
          if (noSt)
            err(0);
          break;
        }
        if (resize)
          cbuf(bt + 131072);
        var end = bt + add3;
        if (bt < dt) {
          var shift = dl - dt, dend = Math.min(dt, end);
          if (shift + bt < 0)
            err(3);
          for (; bt < dend; ++bt)
            buf[bt] = dict[shift + bt];
        }
        for (; bt < end; ++bt)
          buf[bt] = buf[bt - dt];
      }
    }
    st.l = lm, st.p = lpos, st.b = bt, st.f = final;
    if (lm)
      final = 1, st.m = lbt, st.d = dm, st.n = dbt;
  } while (!final);
  return bt != buf.length && noBuf ? slc(buf, 0, bt) : buf.subarray(0, bt);
};
var et = /* @__PURE__ */ new u8(0);
var zls = function(d, dict) {
  if ((d[0] & 15) != 8 || d[0] >> 4 > 7 || (d[0] << 8 | d[1]) % 31)
    err(6, "invalid zlib data");
  if ((d[1] >> 5 & 1) == +!dict)
    err(6, "invalid zlib data: " + (d[1] & 32 ? "need" : "unexpected") + " dictionary");
  return (d[1] >> 3 & 4) + 2;
};
function unzlibSync(data, opts) {
  return inflt(data.subarray(zls(data, opts && opts.dictionary), -4), { i: 2 }, opts && opts.out, opts && opts.dictionary);
}
var td = typeof TextDecoder != "undefined" && /* @__PURE__ */ new TextDecoder();
var tds = 0;
try {
  td.decode(et, { stream: true });
  tds = 1;
} catch (e) {
}

// browser/zlib-shim.js
function inflateSync(data, opts) {
  const input = data instanceof Uint8Array ? data : new Uint8Array(data);
  const max2 = opts && opts.maxOutputLength;
  return max2 ? unzlibSync(input, { out: new Uint8Array(max2) }) : unzlibSync(input);
}

// src/canon.ts
var CanonError = class extends Error {
};
var JS_SAFE_INT_MAX = Number.MAX_SAFE_INTEGER;
function isAscii(s) {
  for (let i2 = 0; i2 < s.length; i2++) if (s.charCodeAt(i2) > 127) return false;
  return true;
}
function canonicalize(v) {
  validate(v);
  return enc(v);
}
function validate(v) {
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new CanonError("floating-point numbers are not allowed");
    if (Math.abs(v) > JS_SAFE_INT_MAX) throw new CanonError("integer outside the JS-safe range");
    return;
  }
  if (Array.isArray(v)) {
    for (const it of v) validate(it);
    return;
  }
  if (v !== null && typeof v === "object") {
    for (const k of Object.keys(v)) {
      if (!isAscii(k)) throw new CanonError("non-ASCII object keys are not allowed");
      validate(v[k]);
    }
  }
}
function enc(v) {
  if (v === null) return "null";
  const t = typeof v;
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") return String(v);
  if (t === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(enc).join(",") + "]";
  const o = v;
  const keys = Object.keys(o).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + enc(o[k])).join(",") + "}";
}

// node_modules/@noble/hashes/esm/crypto.js
var crypto = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0;

// node_modules/@noble/hashes/esm/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("positive integer expected, got " + n);
}
function abytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new Error("Hash should be wrapped by utils.createHasher");
  anumber(h.outputLen);
  anumber(h.blockLen);
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
function clean(...arrays) {
  for (let i2 = 0; i2 < arrays.length; i2++) {
    arrays[i2].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
var hasHexBuiltin = /* @__PURE__ */ (() => (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
))();
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i2) => i2.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
  abytes(bytes);
  if (hasHexBuiltin)
    return bytes.toHex();
  let hex = "";
  for (let i2 = 0; i2 < bytes.length; i2++) {
    hex += hexes[bytes[i2]];
  }
  return hex;
}
var asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
  if (ch >= asciis._0 && ch <= asciis._9)
    return ch - asciis._0;
  if (ch >= asciis.A && ch <= asciis.F)
    return ch - (asciis.A - 10);
  if (ch >= asciis.a && ch <= asciis.f)
    return ch - (asciis.a - 10);
  return;
}
function hexToBytes(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  if (hasHexBuiltin)
    return Uint8Array.fromHex(hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new Error("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  abytes(data);
  return data;
}
function concatBytes(...arrays) {
  let sum = 0;
  for (let i2 = 0; i2 < arrays.length; i2++) {
    const a = arrays[i2];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i2 = 0, pad = 0; i2 < arrays.length; i2++) {
    const a = arrays[i2];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
var Hash = class {
};
function createHasher(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
function randomBytes(bytesLength = 32) {
  if (crypto && typeof crypto.getRandomValues === "function") {
    return crypto.getRandomValues(new Uint8Array(bytesLength));
  }
  if (crypto && typeof crypto.randomBytes === "function") {
    return Uint8Array.from(crypto.randomBytes(bytesLength));
  }
  throw new Error("crypto.getRandomValues must be defined");
}

// node_modules/@noble/hashes/esm/_md.js
function setBigUint64(view, byteOffset, value, isLE2) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE2);
  const _32n3 = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n3 & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE2 ? 4 : 0;
  const l = isLE2 ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE2);
  view.setUint32(byteOffset + l, wl, isLE2);
}
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD = class extends Hash {
  constructor(blockLen, outputLen, padOffset, isLE2) {
    super();
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    data = toBytes(data);
    abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    clean(this.buffer.subarray(pos));
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i2 = pos; i2 < blockLen; i2++)
      buffer[i2] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE2);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i2 = 0; i2 < outLen; i2++)
      oview.setUint32(4 * i2, state[i2], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to || (to = new this.constructor());
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);
var SHA512_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  4089235720,
  3144134277,
  2227873595,
  1013904242,
  4271175723,
  2773480762,
  1595750129,
  1359893119,
  2917565137,
  2600822924,
  725511199,
  528734635,
  4215389547,
  1541459225,
  327033209
]);

// node_modules/@noble/hashes/esm/_u64.js
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i2 = 0; i2 < len; i2++) {
    const { h, l } = fromBig(lst[i2], le);
    [Ah[i2], Al[i2]] = [h, l];
  }
  return [Ah, Al];
}
var shrSH = (h, _l, s) => h >>> s;
var shrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrSH = (h, l, s) => h >>> s | l << 32 - s;
var rotrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
var rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
function add(Ah, Al, Bh, Bl) {
  const l = (Al >>> 0) + (Bl >>> 0);
  return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
}
var add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
var add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
var add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
var add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
var add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
var add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;

// node_modules/@noble/hashes/esm/sha2.js
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA256 = class extends HashMD {
  constructor(outputLen = 32) {
    super(64, outputLen, 8, false);
    this.A = SHA256_IV[0] | 0;
    this.B = SHA256_IV[1] | 0;
    this.C = SHA256_IV[2] | 0;
    this.D = SHA256_IV[3] | 0;
    this.E = SHA256_IV[4] | 0;
    this.F = SHA256_IV[5] | 0;
    this.G = SHA256_IV[6] | 0;
    this.H = SHA256_IV[7] | 0;
  }
  get() {
    const { A, B, C, D: D2, E, F: F2, G, H } = this;
    return [A, B, C, D2, E, F2, G, H];
  }
  // prettier-ignore
  set(A, B, C, D2, E, F2, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D2 | 0;
    this.E = E | 0;
    this.F = F2 | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i2 = 0; i2 < 16; i2++, offset += 4)
      SHA256_W[i2] = view.getUint32(offset, false);
    for (let i2 = 16; i2 < 64; i2++) {
      const W15 = SHA256_W[i2 - 15];
      const W2 = SHA256_W[i2 - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i2] = s1 + SHA256_W[i2 - 7] + s0 + SHA256_W[i2 - 16] | 0;
    }
    let { A, B, C, D: D2, E, F: F2, G, H } = this;
    for (let i2 = 0; i2 < 64; i2++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F2, G) + SHA256_K[i2] + SHA256_W[i2] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F2;
      F2 = E;
      E = D2 + T1 | 0;
      D2 = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D2 = D2 + this.D | 0;
    E = E + this.E | 0;
    F2 = F2 + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D2, E, F2, G, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
};
var K512 = /* @__PURE__ */ (() => split([
  "0x428a2f98d728ae22",
  "0x7137449123ef65cd",
  "0xb5c0fbcfec4d3b2f",
  "0xe9b5dba58189dbbc",
  "0x3956c25bf348b538",
  "0x59f111f1b605d019",
  "0x923f82a4af194f9b",
  "0xab1c5ed5da6d8118",
  "0xd807aa98a3030242",
  "0x12835b0145706fbe",
  "0x243185be4ee4b28c",
  "0x550c7dc3d5ffb4e2",
  "0x72be5d74f27b896f",
  "0x80deb1fe3b1696b1",
  "0x9bdc06a725c71235",
  "0xc19bf174cf692694",
  "0xe49b69c19ef14ad2",
  "0xefbe4786384f25e3",
  "0x0fc19dc68b8cd5b5",
  "0x240ca1cc77ac9c65",
  "0x2de92c6f592b0275",
  "0x4a7484aa6ea6e483",
  "0x5cb0a9dcbd41fbd4",
  "0x76f988da831153b5",
  "0x983e5152ee66dfab",
  "0xa831c66d2db43210",
  "0xb00327c898fb213f",
  "0xbf597fc7beef0ee4",
  "0xc6e00bf33da88fc2",
  "0xd5a79147930aa725",
  "0x06ca6351e003826f",
  "0x142929670a0e6e70",
  "0x27b70a8546d22ffc",
  "0x2e1b21385c26c926",
  "0x4d2c6dfc5ac42aed",
  "0x53380d139d95b3df",
  "0x650a73548baf63de",
  "0x766a0abb3c77b2a8",
  "0x81c2c92e47edaee6",
  "0x92722c851482353b",
  "0xa2bfe8a14cf10364",
  "0xa81a664bbc423001",
  "0xc24b8b70d0f89791",
  "0xc76c51a30654be30",
  "0xd192e819d6ef5218",
  "0xd69906245565a910",
  "0xf40e35855771202a",
  "0x106aa07032bbd1b8",
  "0x19a4c116b8d2d0c8",
  "0x1e376c085141ab53",
  "0x2748774cdf8eeb99",
  "0x34b0bcb5e19b48a8",
  "0x391c0cb3c5c95a63",
  "0x4ed8aa4ae3418acb",
  "0x5b9cca4f7763e373",
  "0x682e6ff3d6b2b8a3",
  "0x748f82ee5defb2fc",
  "0x78a5636f43172f60",
  "0x84c87814a1f0ab72",
  "0x8cc702081a6439ec",
  "0x90befffa23631e28",
  "0xa4506cebde82bde9",
  "0xbef9a3f7b2c67915",
  "0xc67178f2e372532b",
  "0xca273eceea26619c",
  "0xd186b8c721c0c207",
  "0xeada7dd6cde0eb1e",
  "0xf57d4f7fee6ed178",
  "0x06f067aa72176fba",
  "0x0a637dc5a2c898a6",
  "0x113f9804bef90dae",
  "0x1b710b35131c471b",
  "0x28db77f523047d84",
  "0x32caab7b40c72493",
  "0x3c9ebe0a15c9bebc",
  "0x431d67c49c100d4c",
  "0x4cc5d4becb3e42b6",
  "0x597f299cfc657e2a",
  "0x5fcb6fab3ad6faec",
  "0x6c44198c4a475817"
].map((n) => BigInt(n))))();
var SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
var SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
var SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
var SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
var SHA512 = class extends HashMD {
  constructor(outputLen = 64) {
    super(128, outputLen, 16, false);
    this.Ah = SHA512_IV[0] | 0;
    this.Al = SHA512_IV[1] | 0;
    this.Bh = SHA512_IV[2] | 0;
    this.Bl = SHA512_IV[3] | 0;
    this.Ch = SHA512_IV[4] | 0;
    this.Cl = SHA512_IV[5] | 0;
    this.Dh = SHA512_IV[6] | 0;
    this.Dl = SHA512_IV[7] | 0;
    this.Eh = SHA512_IV[8] | 0;
    this.El = SHA512_IV[9] | 0;
    this.Fh = SHA512_IV[10] | 0;
    this.Fl = SHA512_IV[11] | 0;
    this.Gh = SHA512_IV[12] | 0;
    this.Gl = SHA512_IV[13] | 0;
    this.Hh = SHA512_IV[14] | 0;
    this.Hl = SHA512_IV[15] | 0;
  }
  // prettier-ignore
  get() {
    const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
  }
  // prettier-ignore
  set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
    this.Ah = Ah | 0;
    this.Al = Al | 0;
    this.Bh = Bh | 0;
    this.Bl = Bl | 0;
    this.Ch = Ch | 0;
    this.Cl = Cl | 0;
    this.Dh = Dh | 0;
    this.Dl = Dl | 0;
    this.Eh = Eh | 0;
    this.El = El | 0;
    this.Fh = Fh | 0;
    this.Fl = Fl | 0;
    this.Gh = Gh | 0;
    this.Gl = Gl | 0;
    this.Hh = Hh | 0;
    this.Hl = Hl | 0;
  }
  process(view, offset) {
    for (let i2 = 0; i2 < 16; i2++, offset += 4) {
      SHA512_W_H[i2] = view.getUint32(offset);
      SHA512_W_L[i2] = view.getUint32(offset += 4);
    }
    for (let i2 = 16; i2 < 80; i2++) {
      const W15h = SHA512_W_H[i2 - 15] | 0;
      const W15l = SHA512_W_L[i2 - 15] | 0;
      const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
      const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
      const W2h = SHA512_W_H[i2 - 2] | 0;
      const W2l = SHA512_W_L[i2 - 2] | 0;
      const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
      const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
      const SUMl = add4L(s0l, s1l, SHA512_W_L[i2 - 7], SHA512_W_L[i2 - 16]);
      const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i2 - 7], SHA512_W_H[i2 - 16]);
      SHA512_W_H[i2] = SUMh | 0;
      SHA512_W_L[i2] = SUMl | 0;
    }
    let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    for (let i2 = 0; i2 < 80; i2++) {
      const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
      const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
      const CHIh = Eh & Fh ^ ~Eh & Gh;
      const CHIl = El & Fl ^ ~El & Gl;
      const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i2], SHA512_W_L[i2]);
      const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i2], SHA512_W_H[i2]);
      const T1l = T1ll | 0;
      const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
      const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
      const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
      const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
      Hh = Gh | 0;
      Hl = Gl | 0;
      Gh = Fh | 0;
      Gl = Fl | 0;
      Fh = Eh | 0;
      Fl = El | 0;
      ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
      Dh = Ch | 0;
      Dl = Cl | 0;
      Ch = Bh | 0;
      Cl = Bl | 0;
      Bh = Ah | 0;
      Bl = Al | 0;
      const All = add3L(T1l, sigma0l, MAJl);
      Ah = add3H(All, T1h, sigma0h, MAJh);
      Al = All | 0;
    }
    ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
    ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
    ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
    ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
    ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
    ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
    ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
    ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
    this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
  }
  roundClean() {
    clean(SHA512_W_H, SHA512_W_L);
  }
  destroy() {
    clean(this.buffer);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
};
var sha256 = /* @__PURE__ */ createHasher(() => new SHA256());
var sha512 = /* @__PURE__ */ createHasher(() => new SHA512());

// node_modules/@noble/curves/esm/utils.js
var _0n = /* @__PURE__ */ BigInt(0);
var _1n = /* @__PURE__ */ BigInt(1);
function _abool2(value, title = "") {
  if (typeof value !== "boolean") {
    const prefix = title && `"${title}"`;
    throw new Error(prefix + "expected boolean, got type=" + typeof value);
  }
  return value;
}
function _abytes2(value, length, title = "") {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== void 0;
  if (!bytes || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
  }
  return value;
}
function numberToHexUnpadded(num) {
  const hex = num.toString(16);
  return hex.length & 1 ? "0" + hex : hex;
}
function hexToNumber(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  return hex === "" ? _0n : BigInt("0x" + hex);
}
function bytesToNumberBE(bytes) {
  return hexToNumber(bytesToHex(bytes));
}
function bytesToNumberLE(bytes) {
  abytes(bytes);
  return hexToNumber(bytesToHex(Uint8Array.from(bytes).reverse()));
}
function numberToBytesBE(n, len) {
  return hexToBytes(n.toString(16).padStart(len * 2, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function ensureBytes(title, hex, expectedLength) {
  let res;
  if (typeof hex === "string") {
    try {
      res = hexToBytes(hex);
    } catch (e) {
      throw new Error(title + " must be hex string or Uint8Array, cause: " + e);
    }
  } else if (isBytes(hex)) {
    res = Uint8Array.from(hex);
  } else {
    throw new Error(title + " must be hex string or Uint8Array");
  }
  const len = res.length;
  if (typeof expectedLength === "number" && len !== expectedLength)
    throw new Error(title + " of length " + expectedLength + " expected, got " + len);
  return res;
}
function equalBytes(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i2 = 0; i2 < a.length; i2++)
    diff |= a[i2] ^ b[i2];
  return diff === 0;
}
function copyBytes(bytes) {
  return Uint8Array.from(bytes);
}
var isPosBig = (n) => typeof n === "bigint" && _0n <= n;
function inRange(n, min, max2) {
  return isPosBig(n) && isPosBig(min) && isPosBig(max2) && min <= n && n < max2;
}
function aInRange(title, n, min, max2) {
  if (!inRange(n, min, max2))
    throw new Error("expected valid " + title + ": " + min + " <= n < " + max2 + ", got " + n);
}
function bitLen(n) {
  let len;
  for (len = 0; n > _0n; n >>= _1n, len += 1)
    ;
  return len;
}
var bitMask = (n) => (_1n << BigInt(n)) - _1n;
function createHmacDrbg(hashLen, qByteLen, hmacFn) {
  if (typeof hashLen !== "number" || hashLen < 2)
    throw new Error("hashLen must be a number");
  if (typeof qByteLen !== "number" || qByteLen < 2)
    throw new Error("qByteLen must be a number");
  if (typeof hmacFn !== "function")
    throw new Error("hmacFn must be a function");
  const u8n = (len) => new Uint8Array(len);
  const u8of = (byte) => Uint8Array.of(byte);
  let v = u8n(hashLen);
  let k = u8n(hashLen);
  let i2 = 0;
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i2 = 0;
  };
  const h = (...b) => hmacFn(k, v, ...b);
  const reseed = (seed = u8n(0)) => {
    k = h(u8of(0), seed);
    v = h();
    if (seed.length === 0)
      return;
    k = h(u8of(1), seed);
    v = h();
  };
  const gen3 = () => {
    if (i2++ >= 1e3)
      throw new Error("drbg: tried 1000 values");
    let len = 0;
    const out = [];
    while (len < qByteLen) {
      v = h();
      const sl = v.slice();
      out.push(sl);
      len += v.length;
    }
    return concatBytes(...out);
  };
  const genUntil = (seed, pred) => {
    reset();
    reseed(seed);
    let res = void 0;
    while (!(res = pred(gen3())))
      reseed();
    reset();
    return res;
  };
  return genUntil;
}
function _validateObject(object, fields, optFields = {}) {
  if (!object || typeof object !== "object")
    throw new Error("expected valid options object");
  function checkField(fieldName, expectedType, isOpt) {
    const val = object[fieldName];
    if (isOpt && val === void 0)
      return;
    const current = typeof val;
    if (current !== expectedType || val === null)
      throw new Error(`param "${fieldName}" is invalid: expected ${expectedType}, got ${current}`);
  }
  Object.entries(fields).forEach(([k, v]) => checkField(k, v, false));
  Object.entries(optFields).forEach(([k, v]) => checkField(k, v, true));
}
var notImplemented = () => {
  throw new Error("not implemented");
};
function memoized(fn) {
  const map = /* @__PURE__ */ new WeakMap();
  return (arg, ...args) => {
    const val = map.get(arg);
    if (val !== void 0)
      return val;
    const computed = fn(arg, ...args);
    map.set(arg, computed);
    return computed;
  };
}

// node_modules/@noble/curves/esm/abstract/modular.js
var _0n2 = BigInt(0);
var _1n2 = BigInt(1);
var _2n = /* @__PURE__ */ BigInt(2);
var _3n = /* @__PURE__ */ BigInt(3);
var _4n = /* @__PURE__ */ BigInt(4);
var _5n = /* @__PURE__ */ BigInt(5);
var _7n = /* @__PURE__ */ BigInt(7);
var _8n = /* @__PURE__ */ BigInt(8);
var _9n = /* @__PURE__ */ BigInt(9);
var _16n = /* @__PURE__ */ BigInt(16);
function mod(a, b) {
  const result = a % b;
  return result >= _0n2 ? result : b + result;
}
function pow2(x2, power, modulo) {
  let res = x2;
  while (power-- > _0n2) {
    res *= res;
    res %= modulo;
  }
  return res;
}
function invert(number, modulo) {
  if (number === _0n2)
    throw new Error("invert: expected non-zero number");
  if (modulo <= _0n2)
    throw new Error("invert: expected positive modulus, got " + modulo);
  let a = mod(number, modulo);
  let b = modulo;
  let x2 = _0n2, y = _1n2, u = _1n2, v = _0n2;
  while (a !== _0n2) {
    const q = b / a;
    const r = b % a;
    const m = x2 - u * q;
    const n = y - v * q;
    b = a, a = r, x2 = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n2)
    throw new Error("invert: does not exist");
  return mod(x2, modulo);
}
function assertIsSquare(Fp2, root, n) {
  if (!Fp2.eql(Fp2.sqr(root), n))
    throw new Error("Cannot find square root");
}
function sqrt3mod4(Fp2, n) {
  const p1div4 = (Fp2.ORDER + _1n2) / _4n;
  const root = Fp2.pow(n, p1div4);
  assertIsSquare(Fp2, root, n);
  return root;
}
function sqrt5mod8(Fp2, n) {
  const p5div8 = (Fp2.ORDER - _5n) / _8n;
  const n2 = Fp2.mul(n, _2n);
  const v = Fp2.pow(n2, p5div8);
  const nv = Fp2.mul(n, v);
  const i2 = Fp2.mul(Fp2.mul(nv, _2n), v);
  const root = Fp2.mul(nv, Fp2.sub(i2, Fp2.ONE));
  assertIsSquare(Fp2, root, n);
  return root;
}
function sqrt9mod16(P) {
  const Fp_ = Field(P);
  const tn = tonelliShanks(P);
  const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));
  const c2 = tn(Fp_, c1);
  const c3 = tn(Fp_, Fp_.neg(c1));
  const c4 = (P + _7n) / _16n;
  return (Fp2, n) => {
    let tv1 = Fp2.pow(n, c4);
    let tv2 = Fp2.mul(tv1, c1);
    const tv3 = Fp2.mul(tv1, c2);
    const tv4 = Fp2.mul(tv1, c3);
    const e1 = Fp2.eql(Fp2.sqr(tv2), n);
    const e2 = Fp2.eql(Fp2.sqr(tv3), n);
    tv1 = Fp2.cmov(tv1, tv2, e1);
    tv2 = Fp2.cmov(tv4, tv3, e2);
    const e3 = Fp2.eql(Fp2.sqr(tv2), n);
    const root = Fp2.cmov(tv1, tv2, e3);
    assertIsSquare(Fp2, root, n);
    return root;
  };
}
function tonelliShanks(P) {
  if (P < _3n)
    throw new Error("sqrt is not defined for small field");
  let Q2 = P - _1n2;
  let S = 0;
  while (Q2 % _2n === _0n2) {
    Q2 /= _2n;
    S++;
  }
  let Z = _2n;
  const _Fp = Field(P);
  while (FpLegendre(_Fp, Z) === 1) {
    if (Z++ > 1e3)
      throw new Error("Cannot find square root: probably non-prime P");
  }
  if (S === 1)
    return sqrt3mod4;
  let cc = _Fp.pow(Z, Q2);
  const Q1div2 = (Q2 + _1n2) / _2n;
  return function tonelliSlow(Fp2, n) {
    if (Fp2.is0(n))
      return n;
    if (FpLegendre(Fp2, n) !== 1)
      throw new Error("Cannot find square root");
    let M = S;
    let c = Fp2.mul(Fp2.ONE, cc);
    let t = Fp2.pow(n, Q2);
    let R = Fp2.pow(n, Q1div2);
    while (!Fp2.eql(t, Fp2.ONE)) {
      if (Fp2.is0(t))
        return Fp2.ZERO;
      let i2 = 1;
      let t_tmp = Fp2.sqr(t);
      while (!Fp2.eql(t_tmp, Fp2.ONE)) {
        i2++;
        t_tmp = Fp2.sqr(t_tmp);
        if (i2 === M)
          throw new Error("Cannot find square root");
      }
      const exponent = _1n2 << BigInt(M - i2 - 1);
      const b = Fp2.pow(c, exponent);
      M = i2;
      c = Fp2.sqr(b);
      t = Fp2.mul(t, c);
      R = Fp2.mul(R, b);
    }
    return R;
  };
}
function FpSqrt(P) {
  if (P % _4n === _3n)
    return sqrt3mod4;
  if (P % _8n === _5n)
    return sqrt5mod8;
  if (P % _16n === _9n)
    return sqrt9mod16(P);
  return tonelliShanks(P);
}
var isNegativeLE = (num, modulo) => (mod(num, modulo) & _1n2) === _1n2;
var FIELD_FIELDS = [
  "create",
  "isValid",
  "is0",
  "neg",
  "inv",
  "sqrt",
  "sqr",
  "eql",
  "add",
  "sub",
  "mul",
  "pow",
  "div",
  "addN",
  "subN",
  "mulN",
  "sqrN"
];
function validateField(field) {
  const initial = {
    ORDER: "bigint",
    MASK: "bigint",
    BYTES: "number",
    BITS: "number"
  };
  const opts = FIELD_FIELDS.reduce((map, val) => {
    map[val] = "function";
    return map;
  }, initial);
  _validateObject(field, opts);
  return field;
}
function FpPow(Fp2, num, power) {
  if (power < _0n2)
    throw new Error("invalid exponent, negatives unsupported");
  if (power === _0n2)
    return Fp2.ONE;
  if (power === _1n2)
    return num;
  let p = Fp2.ONE;
  let d = num;
  while (power > _0n2) {
    if (power & _1n2)
      p = Fp2.mul(p, d);
    d = Fp2.sqr(d);
    power >>= _1n2;
  }
  return p;
}
function FpInvertBatch(Fp2, nums, passZero = false) {
  const inverted = new Array(nums.length).fill(passZero ? Fp2.ZERO : void 0);
  const multipliedAcc = nums.reduce((acc, num, i2) => {
    if (Fp2.is0(num))
      return acc;
    inverted[i2] = acc;
    return Fp2.mul(acc, num);
  }, Fp2.ONE);
  const invertedAcc = Fp2.inv(multipliedAcc);
  nums.reduceRight((acc, num, i2) => {
    if (Fp2.is0(num))
      return acc;
    inverted[i2] = Fp2.mul(acc, inverted[i2]);
    return Fp2.mul(acc, num);
  }, invertedAcc);
  return inverted;
}
function FpLegendre(Fp2, n) {
  const p1mod2 = (Fp2.ORDER - _1n2) / _2n;
  const powered = Fp2.pow(n, p1mod2);
  const yes = Fp2.eql(powered, Fp2.ONE);
  const zero = Fp2.eql(powered, Fp2.ZERO);
  const no = Fp2.eql(powered, Fp2.neg(Fp2.ONE));
  if (!yes && !zero && !no)
    throw new Error("invalid Legendre symbol result");
  return yes ? 1 : zero ? 0 : -1;
}
function nLength(n, nBitLength) {
  if (nBitLength !== void 0)
    anumber(nBitLength);
  const _nBitLength = nBitLength !== void 0 ? nBitLength : n.toString(2).length;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}
function Field(ORDER, bitLenOrOpts, isLE2 = false, opts = {}) {
  if (ORDER <= _0n2)
    throw new Error("invalid field: expected ORDER > 0, got " + ORDER);
  let _nbitLength = void 0;
  let _sqrt = void 0;
  let modFromBytes = false;
  let allowedLengths = void 0;
  if (typeof bitLenOrOpts === "object" && bitLenOrOpts != null) {
    if (opts.sqrt || isLE2)
      throw new Error("cannot specify opts in two arguments");
    const _opts = bitLenOrOpts;
    if (_opts.BITS)
      _nbitLength = _opts.BITS;
    if (_opts.sqrt)
      _sqrt = _opts.sqrt;
    if (typeof _opts.isLE === "boolean")
      isLE2 = _opts.isLE;
    if (typeof _opts.modFromBytes === "boolean")
      modFromBytes = _opts.modFromBytes;
    allowedLengths = _opts.allowedLengths;
  } else {
    if (typeof bitLenOrOpts === "number")
      _nbitLength = bitLenOrOpts;
    if (opts.sqrt)
      _sqrt = opts.sqrt;
  }
  const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, _nbitLength);
  if (BYTES > 2048)
    throw new Error("invalid field: expected ORDER of <= 2048 bytes");
  let sqrtP;
  const f = Object.freeze({
    ORDER,
    isLE: isLE2,
    BITS,
    BYTES,
    MASK: bitMask(BITS),
    ZERO: _0n2,
    ONE: _1n2,
    allowedLengths,
    create: (num) => mod(num, ORDER),
    isValid: (num) => {
      if (typeof num !== "bigint")
        throw new Error("invalid field element: expected bigint, got " + typeof num);
      return _0n2 <= num && num < ORDER;
    },
    is0: (num) => num === _0n2,
    // is valid and invertible
    isValidNot0: (num) => !f.is0(num) && f.isValid(num),
    isOdd: (num) => (num & _1n2) === _1n2,
    neg: (num) => mod(-num, ORDER),
    eql: (lhs, rhs) => lhs === rhs,
    sqr: (num) => mod(num * num, ORDER),
    add: (lhs, rhs) => mod(lhs + rhs, ORDER),
    sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
    mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
    pow: (num, power) => FpPow(f, num, power),
    div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),
    // Same as above, but doesn't normalize
    sqrN: (num) => num * num,
    addN: (lhs, rhs) => lhs + rhs,
    subN: (lhs, rhs) => lhs - rhs,
    mulN: (lhs, rhs) => lhs * rhs,
    inv: (num) => invert(num, ORDER),
    sqrt: _sqrt || ((n) => {
      if (!sqrtP)
        sqrtP = FpSqrt(ORDER);
      return sqrtP(f, n);
    }),
    toBytes: (num) => isLE2 ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES),
    fromBytes: (bytes, skipValidation = true) => {
      if (allowedLengths) {
        if (!allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
          throw new Error("Field.fromBytes: expected " + allowedLengths + " bytes, got " + bytes.length);
        }
        const padded = new Uint8Array(BYTES);
        padded.set(bytes, isLE2 ? 0 : padded.length - bytes.length);
        bytes = padded;
      }
      if (bytes.length !== BYTES)
        throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
      let scalar = isLE2 ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
      if (modFromBytes)
        scalar = mod(scalar, ORDER);
      if (!skipValidation) {
        if (!f.isValid(scalar))
          throw new Error("invalid field element: outside of range 0..ORDER");
      }
      return scalar;
    },
    // TODO: we don't need it here, move out to separate fn
    invertBatch: (lst) => FpInvertBatch(f, lst),
    // We can't move this out because Fp6, Fp12 implement it
    // and it's unclear what to return in there.
    cmov: (a, b, c) => c ? b : a
  });
  return Object.freeze(f);
}
function getFieldBytesLength(fieldOrder) {
  if (typeof fieldOrder !== "bigint")
    throw new Error("field order must be bigint");
  const bitLength = fieldOrder.toString(2).length;
  return Math.ceil(bitLength / 8);
}
function getMinHashLength(fieldOrder) {
  const length = getFieldBytesLength(fieldOrder);
  return length + Math.ceil(length / 2);
}
function mapHashToField(key, fieldOrder, isLE2 = false) {
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = getMinHashLength(fieldOrder);
  if (len < 16 || len < minLen || len > 1024)
    throw new Error("expected " + minLen + "-1024 bytes of input, got " + len);
  const num = isLE2 ? bytesToNumberLE(key) : bytesToNumberBE(key);
  const reduced = mod(num, fieldOrder - _1n2) + _1n2;
  return isLE2 ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}

// node_modules/@noble/curves/esm/abstract/curve.js
var _0n3 = BigInt(0);
var _1n3 = BigInt(1);
function negateCt(condition, item) {
  const neg = item.negate();
  return condition ? neg : item;
}
function normalizeZ(c, points) {
  const invertedZs = FpInvertBatch(c.Fp, points.map((p) => p.Z));
  return points.map((p, i2) => c.fromAffine(p.toAffine(invertedZs[i2])));
}
function validateW(W, bits2) {
  if (!Number.isSafeInteger(W) || W <= 0 || W > bits2)
    throw new Error("invalid window size, expected [1.." + bits2 + "], got W=" + W);
}
function calcWOpts(W, scalarBits) {
  validateW(W, scalarBits);
  const windows = Math.ceil(scalarBits / W) + 1;
  const windowSize = 2 ** (W - 1);
  const maxNumber = 2 ** W;
  const mask = bitMask(W);
  const shiftBy = BigInt(W);
  return { windows, windowSize, mask, maxNumber, shiftBy };
}
function calcOffsets(n, window, wOpts) {
  const { windowSize, mask, maxNumber, shiftBy } = wOpts;
  let wbits = Number(n & mask);
  let nextN = n >> shiftBy;
  if (wbits > windowSize) {
    wbits -= maxNumber;
    nextN += _1n3;
  }
  const offsetStart = window * windowSize;
  const offset = offsetStart + Math.abs(wbits) - 1;
  const isZero = wbits === 0;
  const isNeg = wbits < 0;
  const isNegF = window % 2 !== 0;
  const offsetF = offsetStart;
  return { nextN, offset, isZero, isNeg, isNegF, offsetF };
}
function validateMSMPoints(points, c) {
  if (!Array.isArray(points))
    throw new Error("array expected");
  points.forEach((p, i2) => {
    if (!(p instanceof c))
      throw new Error("invalid point at index " + i2);
  });
}
function validateMSMScalars(scalars, field) {
  if (!Array.isArray(scalars))
    throw new Error("array of scalars expected");
  scalars.forEach((s, i2) => {
    if (!field.isValid(s))
      throw new Error("invalid scalar at index " + i2);
  });
}
var pointPrecomputes = /* @__PURE__ */ new WeakMap();
var pointWindowSizes = /* @__PURE__ */ new WeakMap();
function getW(P) {
  return pointWindowSizes.get(P) || 1;
}
function assert0(n) {
  if (n !== _0n3)
    throw new Error("invalid wNAF");
}
var wNAF = class {
  // Parametrized with a given Point class (not individual point)
  constructor(Point, bits2) {
    this.BASE = Point.BASE;
    this.ZERO = Point.ZERO;
    this.Fn = Point.Fn;
    this.bits = bits2;
  }
  // non-const time multiplication ladder
  _unsafeLadder(elm, n, p = this.ZERO) {
    let d = elm;
    while (n > _0n3) {
      if (n & _1n3)
        p = p.add(d);
      d = d.double();
      n >>= _1n3;
    }
    return p;
  }
  /**
   * Creates a wNAF precomputation window. Used for caching.
   * Default window size is set by `utils.precompute()` and is equal to 8.
   * Number of precomputed points depends on the curve size:
   * 2^(𝑊−1) * (Math.ceil(𝑛 / 𝑊) + 1), where:
   * - 𝑊 is the window size
   * - 𝑛 is the bitlength of the curve order.
   * For a 256-bit curve and window size 8, the number of precomputed points is 128 * 33 = 4224.
   * @param point Point instance
   * @param W window size
   * @returns precomputed point tables flattened to a single array
   */
  precomputeWindow(point, W) {
    const { windows, windowSize } = calcWOpts(W, this.bits);
    const points = [];
    let p = point;
    let base = p;
    for (let window = 0; window < windows; window++) {
      base = p;
      points.push(base);
      for (let i2 = 1; i2 < windowSize; i2++) {
        base = base.add(p);
        points.push(base);
      }
      p = base.double();
    }
    return points;
  }
  /**
   * Implements ec multiplication using precomputed tables and w-ary non-adjacent form.
   * More compact implementation:
   * https://github.com/paulmillr/noble-secp256k1/blob/47cb1669b6e506ad66b35fe7d76132ae97465da2/index.ts#L502-L541
   * @returns real and fake (for const-time) points
   */
  wNAF(W, precomputes, n) {
    if (!this.Fn.isValid(n))
      throw new Error("invalid scalar");
    let p = this.ZERO;
    let f = this.BASE;
    const wo = calcWOpts(W, this.bits);
    for (let window = 0; window < wo.windows; window++) {
      const { nextN, offset, isZero, isNeg, isNegF, offsetF } = calcOffsets(n, window, wo);
      n = nextN;
      if (isZero) {
        f = f.add(negateCt(isNegF, precomputes[offsetF]));
      } else {
        p = p.add(negateCt(isNeg, precomputes[offset]));
      }
    }
    assert0(n);
    return { p, f };
  }
  /**
   * Implements ec unsafe (non const-time) multiplication using precomputed tables and w-ary non-adjacent form.
   * @param acc accumulator point to add result of multiplication
   * @returns point
   */
  wNAFUnsafe(W, precomputes, n, acc = this.ZERO) {
    const wo = calcWOpts(W, this.bits);
    for (let window = 0; window < wo.windows; window++) {
      if (n === _0n3)
        break;
      const { nextN, offset, isZero, isNeg } = calcOffsets(n, window, wo);
      n = nextN;
      if (isZero) {
        continue;
      } else {
        const item = precomputes[offset];
        acc = acc.add(isNeg ? item.negate() : item);
      }
    }
    assert0(n);
    return acc;
  }
  getPrecomputes(W, point, transform) {
    let comp = pointPrecomputes.get(point);
    if (!comp) {
      comp = this.precomputeWindow(point, W);
      if (W !== 1) {
        if (typeof transform === "function")
          comp = transform(comp);
        pointPrecomputes.set(point, comp);
      }
    }
    return comp;
  }
  cached(point, scalar, transform) {
    const W = getW(point);
    return this.wNAF(W, this.getPrecomputes(W, point, transform), scalar);
  }
  unsafe(point, scalar, transform, prev) {
    const W = getW(point);
    if (W === 1)
      return this._unsafeLadder(point, scalar, prev);
    return this.wNAFUnsafe(W, this.getPrecomputes(W, point, transform), scalar, prev);
  }
  // We calculate precomputes for elliptic curve point multiplication
  // using windowed method. This specifies window size and
  // stores precomputed values. Usually only base point would be precomputed.
  createCache(P, W) {
    validateW(W, this.bits);
    pointWindowSizes.set(P, W);
    pointPrecomputes.delete(P);
  }
  hasCache(elm) {
    return getW(elm) !== 1;
  }
};
function mulEndoUnsafe(Point, point, k1, k2) {
  let acc = point;
  let p1 = Point.ZERO;
  let p2 = Point.ZERO;
  while (k1 > _0n3 || k2 > _0n3) {
    if (k1 & _1n3)
      p1 = p1.add(acc);
    if (k2 & _1n3)
      p2 = p2.add(acc);
    acc = acc.double();
    k1 >>= _1n3;
    k2 >>= _1n3;
  }
  return { p1, p2 };
}
function pippenger(c, fieldN, points, scalars) {
  validateMSMPoints(points, c);
  validateMSMScalars(scalars, fieldN);
  const plength = points.length;
  const slength = scalars.length;
  if (plength !== slength)
    throw new Error("arrays of points and scalars must have equal length");
  const zero = c.ZERO;
  const wbits = bitLen(BigInt(plength));
  let windowSize = 1;
  if (wbits > 12)
    windowSize = wbits - 3;
  else if (wbits > 4)
    windowSize = wbits - 2;
  else if (wbits > 0)
    windowSize = 2;
  const MASK = bitMask(windowSize);
  const buckets = new Array(Number(MASK) + 1).fill(zero);
  const lastBits = Math.floor((fieldN.BITS - 1) / windowSize) * windowSize;
  let sum = zero;
  for (let i2 = lastBits; i2 >= 0; i2 -= windowSize) {
    buckets.fill(zero);
    for (let j = 0; j < slength; j++) {
      const scalar = scalars[j];
      const wbits2 = Number(scalar >> BigInt(i2) & MASK);
      buckets[wbits2] = buckets[wbits2].add(points[j]);
    }
    let resI = zero;
    for (let j = buckets.length - 1, sumI = zero; j > 0; j--) {
      sumI = sumI.add(buckets[j]);
      resI = resI.add(sumI);
    }
    sum = sum.add(resI);
    if (i2 !== 0)
      for (let j = 0; j < windowSize; j++)
        sum = sum.double();
  }
  return sum;
}
function createField(order, field, isLE2) {
  if (field) {
    if (field.ORDER !== order)
      throw new Error("Field.ORDER must match order: Fp == p, Fn == n");
    validateField(field);
    return field;
  } else {
    return Field(order, { isLE: isLE2 });
  }
}
function _createCurveFields(type, CURVE, curveOpts = {}, FpFnLE) {
  if (FpFnLE === void 0)
    FpFnLE = type === "edwards";
  if (!CURVE || typeof CURVE !== "object")
    throw new Error(`expected valid ${type} CURVE object`);
  for (const p of ["p", "n", "h"]) {
    const val = CURVE[p];
    if (!(typeof val === "bigint" && val > _0n3))
      throw new Error(`CURVE.${p} must be positive bigint`);
  }
  const Fp2 = createField(CURVE.p, curveOpts.Fp, FpFnLE);
  const Fn2 = createField(CURVE.n, curveOpts.Fn, FpFnLE);
  const _b2 = type === "weierstrass" ? "b" : "d";
  const params2 = ["Gx", "Gy", "a", _b2];
  for (const p of params2) {
    if (!Fp2.isValid(CURVE[p]))
      throw new Error(`CURVE.${p} must be valid field element of CURVE.Fp`);
  }
  CURVE = Object.freeze(Object.assign({}, CURVE));
  return { CURVE, Fp: Fp2, Fn: Fn2 };
}

// node_modules/@noble/curves/esm/abstract/edwards.js
var _0n4 = BigInt(0);
var _1n4 = BigInt(1);
var _2n2 = BigInt(2);
var _8n2 = BigInt(8);
function isEdValidXY(Fp2, CURVE, x2, y) {
  const x22 = Fp2.sqr(x2);
  const y2 = Fp2.sqr(y);
  const left = Fp2.add(Fp2.mul(CURVE.a, x22), y2);
  const right = Fp2.add(Fp2.ONE, Fp2.mul(CURVE.d, Fp2.mul(x22, y2)));
  return Fp2.eql(left, right);
}
function edwards(params2, extraOpts = {}) {
  const validated = _createCurveFields("edwards", params2, extraOpts, extraOpts.FpFnLE);
  const { Fp: Fp2, Fn: Fn2 } = validated;
  let CURVE = validated.CURVE;
  const { h: cofactor } = CURVE;
  _validateObject(extraOpts, {}, { uvRatio: "function" });
  const MASK = _2n2 << BigInt(Fn2.BYTES * 8) - _1n4;
  const modP = (n) => Fp2.create(n);
  const uvRatio2 = extraOpts.uvRatio || ((u, v) => {
    try {
      return { isValid: true, value: Fp2.sqrt(Fp2.div(u, v)) };
    } catch (e) {
      return { isValid: false, value: _0n4 };
    }
  });
  if (!isEdValidXY(Fp2, CURVE, CURVE.Gx, CURVE.Gy))
    throw new Error("bad curve params: generator point");
  function acoord(title, n, banZero = false) {
    const min = banZero ? _1n4 : _0n4;
    aInRange("coordinate " + title, n, min, MASK);
    return n;
  }
  function aextpoint(other) {
    if (!(other instanceof Point))
      throw new Error("ExtendedPoint expected");
  }
  const toAffineMemo = memoized((p, iz) => {
    const { X, Y, Z } = p;
    const is0 = p.is0();
    if (iz == null)
      iz = is0 ? _8n2 : Fp2.inv(Z);
    const x2 = modP(X * iz);
    const y = modP(Y * iz);
    const zz = Fp2.mul(Z, iz);
    if (is0)
      return { x: _0n4, y: _1n4 };
    if (zz !== _1n4)
      throw new Error("invZ was invalid");
    return { x: x2, y };
  });
  const assertValidMemo = memoized((p) => {
    const { a, d } = CURVE;
    if (p.is0())
      throw new Error("bad point: ZERO");
    const { X, Y, Z, T } = p;
    const X2 = modP(X * X);
    const Y2 = modP(Y * Y);
    const Z2 = modP(Z * Z);
    const Z4 = modP(Z2 * Z2);
    const aX2 = modP(X2 * a);
    const left = modP(Z2 * modP(aX2 + Y2));
    const right = modP(Z4 + modP(d * modP(X2 * Y2)));
    if (left !== right)
      throw new Error("bad point: equation left != right (1)");
    const XY = modP(X * Y);
    const ZT = modP(Z * T);
    if (XY !== ZT)
      throw new Error("bad point: equation left != right (2)");
    return true;
  });
  class Point {
    constructor(X, Y, Z, T) {
      this.X = acoord("x", X);
      this.Y = acoord("y", Y);
      this.Z = acoord("z", Z, true);
      this.T = acoord("t", T);
      Object.freeze(this);
    }
    static CURVE() {
      return CURVE;
    }
    static fromAffine(p) {
      if (p instanceof Point)
        throw new Error("extended point not allowed");
      const { x: x2, y } = p || {};
      acoord("x", x2);
      acoord("y", y);
      return new Point(x2, y, _1n4, modP(x2 * y));
    }
    // Uses algo from RFC8032 5.1.3.
    static fromBytes(bytes, zip215 = false) {
      const len = Fp2.BYTES;
      const { a, d } = CURVE;
      bytes = copyBytes(_abytes2(bytes, len, "point"));
      _abool2(zip215, "zip215");
      const normed = copyBytes(bytes);
      const lastByte = bytes[len - 1];
      normed[len - 1] = lastByte & ~128;
      const y = bytesToNumberLE(normed);
      const max2 = zip215 ? MASK : Fp2.ORDER;
      aInRange("point.y", y, _0n4, max2);
      const y2 = modP(y * y);
      const u = modP(y2 - _1n4);
      const v = modP(d * y2 - a);
      let { isValid, value: x2 } = uvRatio2(u, v);
      if (!isValid)
        throw new Error("bad point: invalid y coordinate");
      const isXOdd = (x2 & _1n4) === _1n4;
      const isLastByteOdd = (lastByte & 128) !== 0;
      if (!zip215 && x2 === _0n4 && isLastByteOdd)
        throw new Error("bad point: x=0 and x_0=1");
      if (isLastByteOdd !== isXOdd)
        x2 = modP(-x2);
      return Point.fromAffine({ x: x2, y });
    }
    static fromHex(bytes, zip215 = false) {
      return Point.fromBytes(ensureBytes("point", bytes), zip215);
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    precompute(windowSize = 8, isLazy = true) {
      wnaf.createCache(this, windowSize);
      if (!isLazy)
        this.multiply(_2n2);
      return this;
    }
    // Useful in fromAffine() - not for fromBytes(), which always created valid points.
    assertValidity() {
      assertValidMemo(this);
    }
    // Compare one point to another.
    equals(other) {
      aextpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      const X1Z2 = modP(X1 * Z2);
      const X2Z1 = modP(X2 * Z1);
      const Y1Z2 = modP(Y1 * Z2);
      const Y2Z1 = modP(Y2 * Z1);
      return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }
    is0() {
      return this.equals(Point.ZERO);
    }
    negate() {
      return new Point(modP(-this.X), this.Y, this.Z, modP(-this.T));
    }
    // Fast algo for doubling Extended Point.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
    // Cost: 4M + 4S + 1*a + 6add + 1*2.
    double() {
      const { a } = CURVE;
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const A = modP(X1 * X1);
      const B = modP(Y1 * Y1);
      const C = modP(_2n2 * modP(Z1 * Z1));
      const D2 = modP(a * A);
      const x1y1 = X1 + Y1;
      const E = modP(modP(x1y1 * x1y1) - A - B);
      const G = D2 + B;
      const F2 = G - C;
      const H = D2 - B;
      const X3 = modP(E * F2);
      const Y3 = modP(G * H);
      const T3 = modP(E * H);
      const Z3 = modP(F2 * G);
      return new Point(X3, Y3, Z3, T3);
    }
    // Fast algo for adding 2 Extended Points.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
    // Cost: 9M + 1*a + 1*d + 7add.
    add(other) {
      aextpoint(other);
      const { a, d } = CURVE;
      const { X: X1, Y: Y1, Z: Z1, T: T1 } = this;
      const { X: X2, Y: Y2, Z: Z2, T: T2 } = other;
      const A = modP(X1 * X2);
      const B = modP(Y1 * Y2);
      const C = modP(T1 * d * T2);
      const D2 = modP(Z1 * Z2);
      const E = modP((X1 + Y1) * (X2 + Y2) - A - B);
      const F2 = D2 - C;
      const G = D2 + C;
      const H = modP(B - a * A);
      const X3 = modP(E * F2);
      const Y3 = modP(G * H);
      const T3 = modP(E * H);
      const Z3 = modP(F2 * G);
      return new Point(X3, Y3, Z3, T3);
    }
    subtract(other) {
      return this.add(other.negate());
    }
    // Constant-time multiplication.
    multiply(scalar) {
      if (!Fn2.isValidNot0(scalar))
        throw new Error("invalid scalar: expected 1 <= sc < curve.n");
      const { p, f } = wnaf.cached(this, scalar, (p2) => normalizeZ(Point, p2));
      return normalizeZ(Point, [p, f])[0];
    }
    // Non-constant-time multiplication. Uses double-and-add algorithm.
    // It's faster, but should only be used when you don't care about
    // an exposed private key e.g. sig verification.
    // Does NOT allow scalars higher than CURVE.n.
    // Accepts optional accumulator to merge with multiply (important for sparse scalars)
    multiplyUnsafe(scalar, acc = Point.ZERO) {
      if (!Fn2.isValid(scalar))
        throw new Error("invalid scalar: expected 0 <= sc < curve.n");
      if (scalar === _0n4)
        return Point.ZERO;
      if (this.is0() || scalar === _1n4)
        return this;
      return wnaf.unsafe(this, scalar, (p) => normalizeZ(Point, p), acc);
    }
    // Checks if point is of small order.
    // If you add something to small order point, you will have "dirty"
    // point with torsion component.
    // Multiplies point by cofactor and checks if the result is 0.
    isSmallOrder() {
      return this.multiplyUnsafe(cofactor).is0();
    }
    // Multiplies point by curve order and checks if the result is 0.
    // Returns `false` is the point is dirty.
    isTorsionFree() {
      return wnaf.unsafe(this, CURVE.n).is0();
    }
    // Converts Extended point to default (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    toAffine(invertedZ) {
      return toAffineMemo(this, invertedZ);
    }
    clearCofactor() {
      if (cofactor === _1n4)
        return this;
      return this.multiplyUnsafe(cofactor);
    }
    toBytes() {
      const { x: x2, y } = this.toAffine();
      const bytes = Fp2.toBytes(y);
      bytes[bytes.length - 1] |= x2 & _1n4 ? 128 : 0;
      return bytes;
    }
    toHex() {
      return bytesToHex(this.toBytes());
    }
    toString() {
      return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
    }
    // TODO: remove
    get ex() {
      return this.X;
    }
    get ey() {
      return this.Y;
    }
    get ez() {
      return this.Z;
    }
    get et() {
      return this.T;
    }
    static normalizeZ(points) {
      return normalizeZ(Point, points);
    }
    static msm(points, scalars) {
      return pippenger(Point, Fn2, points, scalars);
    }
    _setWindowSize(windowSize) {
      this.precompute(windowSize);
    }
    toRawBytes() {
      return this.toBytes();
    }
  }
  Point.BASE = new Point(CURVE.Gx, CURVE.Gy, _1n4, modP(CURVE.Gx * CURVE.Gy));
  Point.ZERO = new Point(_0n4, _1n4, _1n4, _0n4);
  Point.Fp = Fp2;
  Point.Fn = Fn2;
  const wnaf = new wNAF(Point, Fn2.BITS);
  Point.BASE.precompute(8);
  return Point;
}
var PrimeEdwardsPoint = class {
  constructor(ep) {
    this.ep = ep;
  }
  // Static methods that must be implemented by subclasses
  static fromBytes(_bytes) {
    notImplemented();
  }
  static fromHex(_hex) {
    notImplemented();
  }
  get x() {
    return this.toAffine().x;
  }
  get y() {
    return this.toAffine().y;
  }
  // Common implementations
  clearCofactor() {
    return this;
  }
  assertValidity() {
    this.ep.assertValidity();
  }
  toAffine(invertedZ) {
    return this.ep.toAffine(invertedZ);
  }
  toHex() {
    return bytesToHex(this.toBytes());
  }
  toString() {
    return this.toHex();
  }
  isTorsionFree() {
    return true;
  }
  isSmallOrder() {
    return false;
  }
  add(other) {
    this.assertSame(other);
    return this.init(this.ep.add(other.ep));
  }
  subtract(other) {
    this.assertSame(other);
    return this.init(this.ep.subtract(other.ep));
  }
  multiply(scalar) {
    return this.init(this.ep.multiply(scalar));
  }
  multiplyUnsafe(scalar) {
    return this.init(this.ep.multiplyUnsafe(scalar));
  }
  double() {
    return this.init(this.ep.double());
  }
  negate() {
    return this.init(this.ep.negate());
  }
  precompute(windowSize, isLazy) {
    return this.init(this.ep.precompute(windowSize, isLazy));
  }
  /** @deprecated use `toBytes` */
  toRawBytes() {
    return this.toBytes();
  }
};
function eddsa(Point, cHash, eddsaOpts = {}) {
  if (typeof cHash !== "function")
    throw new Error('"hash" function param is required');
  _validateObject(eddsaOpts, {}, {
    adjustScalarBytes: "function",
    randomBytes: "function",
    domain: "function",
    prehash: "function",
    mapToCurve: "function"
  });
  const { prehash } = eddsaOpts;
  const { BASE, Fp: Fp2, Fn: Fn2 } = Point;
  const randomBytes4 = eddsaOpts.randomBytes || randomBytes;
  const adjustScalarBytes2 = eddsaOpts.adjustScalarBytes || ((bytes) => bytes);
  const domain = eddsaOpts.domain || ((data, ctx, phflag) => {
    _abool2(phflag, "phflag");
    if (ctx.length || phflag)
      throw new Error("Contexts/pre-hash are not supported");
    return data;
  });
  function modN_LE(hash) {
    return Fn2.create(bytesToNumberLE(hash));
  }
  function getPrivateScalar(key) {
    const len = lengths.secretKey;
    key = ensureBytes("private key", key, len);
    const hashed = ensureBytes("hashed private key", cHash(key), 2 * len);
    const head = adjustScalarBytes2(hashed.slice(0, len));
    const prefix = hashed.slice(len, 2 * len);
    const scalar = modN_LE(head);
    return { head, prefix, scalar };
  }
  function getExtendedPublicKey(secretKey) {
    const { head, prefix, scalar } = getPrivateScalar(secretKey);
    const point = BASE.multiply(scalar);
    const pointBytes = point.toBytes();
    return { head, prefix, scalar, point, pointBytes };
  }
  function getPublicKey(secretKey) {
    return getExtendedPublicKey(secretKey).pointBytes;
  }
  function hashDomainToScalar(context = Uint8Array.of(), ...msgs) {
    const msg = concatBytes(...msgs);
    return modN_LE(cHash(domain(msg, ensureBytes("context", context), !!prehash)));
  }
  function sign(msg, secretKey, options = {}) {
    msg = ensureBytes("message", msg);
    if (prehash)
      msg = prehash(msg);
    const { prefix, scalar, pointBytes } = getExtendedPublicKey(secretKey);
    const r = hashDomainToScalar(options.context, prefix, msg);
    const R = BASE.multiply(r).toBytes();
    const k = hashDomainToScalar(options.context, R, pointBytes, msg);
    const s = Fn2.create(r + k * scalar);
    if (!Fn2.isValid(s))
      throw new Error("sign failed: invalid s");
    const rs = concatBytes(R, Fn2.toBytes(s));
    return _abytes2(rs, lengths.signature, "result");
  }
  const verifyOpts = { zip215: true };
  function verify2(sig, msg, publicKey, options = verifyOpts) {
    const { context, zip215 } = options;
    const len = lengths.signature;
    sig = ensureBytes("signature", sig, len);
    msg = ensureBytes("message", msg);
    publicKey = ensureBytes("publicKey", publicKey, lengths.publicKey);
    if (zip215 !== void 0)
      _abool2(zip215, "zip215");
    if (prehash)
      msg = prehash(msg);
    const mid = len / 2;
    const r = sig.subarray(0, mid);
    const s = bytesToNumberLE(sig.subarray(mid, len));
    let A, R, SB;
    try {
      A = Point.fromBytes(publicKey, zip215);
      R = Point.fromBytes(r, zip215);
      SB = BASE.multiplyUnsafe(s);
    } catch (error) {
      return false;
    }
    if (!zip215 && A.isSmallOrder())
      return false;
    const k = hashDomainToScalar(context, R.toBytes(), A.toBytes(), msg);
    const RkA = R.add(A.multiplyUnsafe(k));
    return RkA.subtract(SB).clearCofactor().is0();
  }
  const _size = Fp2.BYTES;
  const lengths = {
    secretKey: _size,
    publicKey: _size,
    signature: 2 * _size,
    seed: _size
  };
  function randomSecretKey(seed = randomBytes4(lengths.seed)) {
    return _abytes2(seed, lengths.seed, "seed");
  }
  function keygen(seed) {
    const secretKey = utils.randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey(secretKey) };
  }
  function isValidSecretKey(key) {
    return isBytes(key) && key.length === Fn2.BYTES;
  }
  function isValidPublicKey(key, zip215) {
    try {
      return !!Point.fromBytes(key, zip215);
    } catch (error) {
      return false;
    }
  }
  const utils = {
    getExtendedPublicKey,
    randomSecretKey,
    isValidSecretKey,
    isValidPublicKey,
    /**
     * Converts ed public key to x public key. Uses formula:
     * - ed25519:
     *   - `(u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)`
     *   - `(x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))`
     * - ed448:
     *   - `(u, v) = ((y-1)/(y+1), sqrt(156324)*u/x)`
     *   - `(x, y) = (sqrt(156324)*u/v, (1+u)/(1-u))`
     */
    toMontgomery(publicKey) {
      const { y } = Point.fromBytes(publicKey);
      const size = lengths.publicKey;
      const is25519 = size === 32;
      if (!is25519 && size !== 57)
        throw new Error("only defined for 25519 and 448");
      const u = is25519 ? Fp2.div(_1n4 + y, _1n4 - y) : Fp2.div(y - _1n4, y + _1n4);
      return Fp2.toBytes(u);
    },
    toMontgomerySecret(secretKey) {
      const size = lengths.secretKey;
      _abytes2(secretKey, size);
      const hashed = cHash(secretKey.subarray(0, size));
      return adjustScalarBytes2(hashed).subarray(0, size);
    },
    /** @deprecated */
    randomPrivateKey: randomSecretKey,
    /** @deprecated */
    precompute(windowSize = 8, point = Point.BASE) {
      return point.precompute(windowSize, false);
    }
  };
  return Object.freeze({
    keygen,
    getPublicKey,
    sign,
    verify: verify2,
    utils,
    Point,
    lengths
  });
}
function _eddsa_legacy_opts_to_new(c) {
  const CURVE = {
    a: c.a,
    d: c.d,
    p: c.Fp.ORDER,
    n: c.n,
    h: c.h,
    Gx: c.Gx,
    Gy: c.Gy
  };
  const Fp2 = c.Fp;
  const Fn2 = Field(CURVE.n, c.nBitLength, true);
  const curveOpts = { Fp: Fp2, Fn: Fn2, uvRatio: c.uvRatio };
  const eddsaOpts = {
    randomBytes: c.randomBytes,
    adjustScalarBytes: c.adjustScalarBytes,
    domain: c.domain,
    prehash: c.prehash,
    mapToCurve: c.mapToCurve
  };
  return { CURVE, curveOpts, hash: c.hash, eddsaOpts };
}
function _eddsa_new_output_to_legacy(c, eddsa2) {
  const Point = eddsa2.Point;
  const legacy = Object.assign({}, eddsa2, {
    ExtendedPoint: Point,
    CURVE: c,
    nBitLength: Point.Fn.BITS,
    nByteLength: Point.Fn.BYTES
  });
  return legacy;
}
function twistedEdwards(c) {
  const { CURVE, curveOpts, hash, eddsaOpts } = _eddsa_legacy_opts_to_new(c);
  const Point = edwards(CURVE, curveOpts);
  const EDDSA = eddsa(Point, hash, eddsaOpts);
  return _eddsa_new_output_to_legacy(c, EDDSA);
}

// node_modules/@noble/curves/esm/ed25519.js
var _0n5 = /* @__PURE__ */ BigInt(0);
var _1n5 = BigInt(1);
var _2n3 = BigInt(2);
var _3n2 = BigInt(3);
var _5n2 = BigInt(5);
var _8n3 = BigInt(8);
var ed25519_CURVE_p = BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
var ed25519_CURVE = /* @__PURE__ */ (() => ({
  p: ed25519_CURVE_p,
  n: BigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
  h: _8n3,
  a: BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"),
  d: BigInt("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"),
  Gx: BigInt("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"),
  Gy: BigInt("0x6666666666666666666666666666666666666666666666666666666666666658")
}))();
function ed25519_pow_2_252_3(x2) {
  const _10n = BigInt(10), _20n = BigInt(20), _40n = BigInt(40), _80n = BigInt(80);
  const P = ed25519_CURVE_p;
  const x22 = x2 * x2 % P;
  const b2 = x22 * x2 % P;
  const b4 = pow2(b2, _2n3, P) * b2 % P;
  const b5 = pow2(b4, _1n5, P) * x2 % P;
  const b10 = pow2(b5, _5n2, P) * b5 % P;
  const b20 = pow2(b10, _10n, P) * b10 % P;
  const b40 = pow2(b20, _20n, P) * b20 % P;
  const b80 = pow2(b40, _40n, P) * b40 % P;
  const b160 = pow2(b80, _80n, P) * b80 % P;
  const b240 = pow2(b160, _80n, P) * b80 % P;
  const b250 = pow2(b240, _10n, P) * b10 % P;
  const pow_p_5_8 = pow2(b250, _2n3, P) * x2 % P;
  return { pow_p_5_8, b2 };
}
function adjustScalarBytes(bytes) {
  bytes[0] &= 248;
  bytes[31] &= 127;
  bytes[31] |= 64;
  return bytes;
}
var ED25519_SQRT_M1 = /* @__PURE__ */ BigInt("19681161376707505956807079304988542015446066515923890162744021073123829784752");
function uvRatio(u, v) {
  const P = ed25519_CURVE_p;
  const v3 = mod(v * v * v, P);
  const v7 = mod(v3 * v3 * v, P);
  const pow = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
  let x2 = mod(u * v3 * pow, P);
  const vx2 = mod(v * x2 * x2, P);
  const root1 = x2;
  const root2 = mod(x2 * ED25519_SQRT_M1, P);
  const useRoot1 = vx2 === u;
  const useRoot2 = vx2 === mod(-u, P);
  const noRoot = vx2 === mod(-u * ED25519_SQRT_M1, P);
  if (useRoot1)
    x2 = root1;
  if (useRoot2 || noRoot)
    x2 = root2;
  if (isNegativeLE(x2, P))
    x2 = mod(-x2, P);
  return { isValid: useRoot1 || useRoot2, value: x2 };
}
var Fp = /* @__PURE__ */ (() => Field(ed25519_CURVE.p, { isLE: true }))();
var Fn = /* @__PURE__ */ (() => Field(ed25519_CURVE.n, { isLE: true }))();
var ed25519Defaults = /* @__PURE__ */ (() => ({
  ...ed25519_CURVE,
  Fp,
  hash: sha512,
  adjustScalarBytes,
  // dom2
  // Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
  // Constant-time, u/√v
  uvRatio
}))();
var ed25519 = /* @__PURE__ */ (() => twistedEdwards(ed25519Defaults))();
var SQRT_M1 = ED25519_SQRT_M1;
var SQRT_AD_MINUS_ONE = /* @__PURE__ */ BigInt("25063068953384623474111414158702152701244531502492656460079210482610430750235");
var INVSQRT_A_MINUS_D = /* @__PURE__ */ BigInt("54469307008909316920995813868745141605393597292927456921205312896311721017578");
var ONE_MINUS_D_SQ = /* @__PURE__ */ BigInt("1159843021668779879193775521855586647937357759715417654439879720876111806838");
var D_MINUS_ONE_SQ = /* @__PURE__ */ BigInt("40440834346308536858101042469323190826248399146238708352240133220865137265952");
var invertSqrt = (number) => uvRatio(_1n5, number);
var MAX_255B = /* @__PURE__ */ BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
var bytes255ToNumberLE = (bytes) => ed25519.Point.Fp.create(bytesToNumberLE(bytes) & MAX_255B);
function calcElligatorRistrettoMap(r0) {
  const { d } = ed25519_CURVE;
  const P = ed25519_CURVE_p;
  const mod3 = (n) => Fp.create(n);
  const r = mod3(SQRT_M1 * r0 * r0);
  const Ns = mod3((r + _1n5) * ONE_MINUS_D_SQ);
  let c = BigInt(-1);
  const D2 = mod3((c - d * r) * mod3(r + d));
  let { isValid: Ns_D_is_sq, value: s } = uvRatio(Ns, D2);
  let s_ = mod3(s * r0);
  if (!isNegativeLE(s_, P))
    s_ = mod3(-s_);
  if (!Ns_D_is_sq)
    s = s_;
  if (!Ns_D_is_sq)
    c = r;
  const Nt = mod3(c * (r - _1n5) * D_MINUS_ONE_SQ - D2);
  const s2 = s * s;
  const W0 = mod3((s + s) * D2);
  const W1 = mod3(Nt * SQRT_AD_MINUS_ONE);
  const W2 = mod3(_1n5 - s2);
  const W3 = mod3(_1n5 + s2);
  return new ed25519.Point(mod3(W0 * W3), mod3(W2 * W1), mod3(W1 * W3), mod3(W0 * W2));
}
function ristretto255_map(bytes) {
  abytes(bytes, 64);
  const r1 = bytes255ToNumberLE(bytes.subarray(0, 32));
  const R1 = calcElligatorRistrettoMap(r1);
  const r2 = bytes255ToNumberLE(bytes.subarray(32, 64));
  const R2 = calcElligatorRistrettoMap(r2);
  return new _RistrettoPoint(R1.add(R2));
}
var _RistrettoPoint = class __RistrettoPoint extends PrimeEdwardsPoint {
  constructor(ep) {
    super(ep);
  }
  static fromAffine(ap) {
    return new __RistrettoPoint(ed25519.Point.fromAffine(ap));
  }
  assertSame(other) {
    if (!(other instanceof __RistrettoPoint))
      throw new Error("RistrettoPoint expected");
  }
  init(ep) {
    return new __RistrettoPoint(ep);
  }
  /** @deprecated use `import { ristretto255_hasher } from '@noble/curves/ed25519.js';` */
  static hashToCurve(hex) {
    return ristretto255_map(ensureBytes("ristrettoHash", hex, 64));
  }
  static fromBytes(bytes) {
    abytes(bytes, 32);
    const { a, d } = ed25519_CURVE;
    const P = ed25519_CURVE_p;
    const mod3 = (n) => Fp.create(n);
    const s = bytes255ToNumberLE(bytes);
    if (!equalBytes(Fp.toBytes(s), bytes) || isNegativeLE(s, P))
      throw new Error("invalid ristretto255 encoding 1");
    const s2 = mod3(s * s);
    const u1 = mod3(_1n5 + a * s2);
    const u2 = mod3(_1n5 - a * s2);
    const u1_2 = mod3(u1 * u1);
    const u2_2 = mod3(u2 * u2);
    const v = mod3(a * d * u1_2 - u2_2);
    const { isValid, value: I } = invertSqrt(mod3(v * u2_2));
    const Dx = mod3(I * u2);
    const Dy = mod3(I * Dx * v);
    let x2 = mod3((s + s) * Dx);
    if (isNegativeLE(x2, P))
      x2 = mod3(-x2);
    const y = mod3(u1 * Dy);
    const t = mod3(x2 * y);
    if (!isValid || isNegativeLE(t, P) || y === _0n5)
      throw new Error("invalid ristretto255 encoding 2");
    return new __RistrettoPoint(new ed25519.Point(x2, y, _1n5, t));
  }
  /**
   * Converts ristretto-encoded string to ristretto point.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-decode).
   * @param hex Ristretto-encoded 32 bytes. Not every 32-byte string is valid ristretto encoding
   */
  static fromHex(hex) {
    return __RistrettoPoint.fromBytes(ensureBytes("ristrettoHex", hex, 32));
  }
  static msm(points, scalars) {
    return pippenger(__RistrettoPoint, ed25519.Point.Fn, points, scalars);
  }
  /**
   * Encodes ristretto point to Uint8Array.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-encode).
   */
  toBytes() {
    let { X, Y, Z, T } = this.ep;
    const P = ed25519_CURVE_p;
    const mod3 = (n) => Fp.create(n);
    const u1 = mod3(mod3(Z + Y) * mod3(Z - Y));
    const u2 = mod3(X * Y);
    const u2sq = mod3(u2 * u2);
    const { value: invsqrt } = invertSqrt(mod3(u1 * u2sq));
    const D1 = mod3(invsqrt * u1);
    const D2 = mod3(invsqrt * u2);
    const zInv = mod3(D1 * D2 * T);
    let D3;
    if (isNegativeLE(T * zInv, P)) {
      let _x = mod3(Y * SQRT_M1);
      let _y = mod3(X * SQRT_M1);
      X = _x;
      Y = _y;
      D3 = mod3(D1 * INVSQRT_A_MINUS_D);
    } else {
      D3 = D2;
    }
    if (isNegativeLE(X * zInv, P))
      Y = mod3(-Y);
    let s = mod3((Z - Y) * D3);
    if (isNegativeLE(s, P))
      s = mod3(-s);
    return Fp.toBytes(s);
  }
  /**
   * Compares two Ristretto points.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-equals).
   */
  equals(other) {
    this.assertSame(other);
    const { X: X1, Y: Y1 } = this.ep;
    const { X: X2, Y: Y2 } = other.ep;
    const mod3 = (n) => Fp.create(n);
    const one = mod3(X1 * Y2) === mod3(Y1 * X2);
    const two = mod3(Y1 * Y2) === mod3(X1 * X2);
    return one || two;
  }
  is0() {
    return this.equals(__RistrettoPoint.ZERO);
  }
};
_RistrettoPoint.BASE = /* @__PURE__ */ (() => new _RistrettoPoint(ed25519.Point.BASE))();
_RistrettoPoint.ZERO = /* @__PURE__ */ (() => new _RistrettoPoint(ed25519.Point.ZERO))();
_RistrettoPoint.Fp = /* @__PURE__ */ (() => Fp)();
_RistrettoPoint.Fn = /* @__PURE__ */ (() => Fn)();

// node_modules/@noble/hashes/esm/hmac.js
var HMAC = class extends Hash {
  constructor(hash, _key) {
    super();
    this.finished = false;
    this.destroyed = false;
    ahash(hash);
    const key = toBytes(_key);
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("Expected instance of class which extends utils.Hash");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i2 = 0; i2 < pad.length; i2++)
      pad[i2] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash.create();
    for (let i2 = 0; i2 < pad.length; i2++)
      pad[i2] ^= 54 ^ 92;
    this.oHash.update(pad);
    clean(pad);
  }
  update(buf) {
    aexists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    aexists(this);
    abytes(out, this.outputLen);
    this.finished = true;
    this.iHash.digestInto(out);
    this.oHash.update(out);
    this.oHash.digestInto(out);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to || (to = Object.create(Object.getPrototypeOf(this), {}));
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
};
var hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
hmac.create = (hash, key) => new HMAC(hash, key);

// node_modules/@noble/curves/esm/abstract/weierstrass.js
var divNearest = (num, den) => (num + (num >= 0 ? den : -den) / _2n4) / den;
function _splitEndoScalar(k, basis, n) {
  const [[a1, b1], [a2, b2]] = basis;
  const c1 = divNearest(b2 * k, n);
  const c2 = divNearest(-b1 * k, n);
  let k1 = k - c1 * a1 - c2 * a2;
  let k2 = -c1 * b1 - c2 * b2;
  const k1neg = k1 < _0n6;
  const k2neg = k2 < _0n6;
  if (k1neg)
    k1 = -k1;
  if (k2neg)
    k2 = -k2;
  const MAX_NUM = bitMask(Math.ceil(bitLen(n) / 2)) + _1n6;
  if (k1 < _0n6 || k1 >= MAX_NUM || k2 < _0n6 || k2 >= MAX_NUM) {
    throw new Error("splitScalar (endomorphism): failed, k=" + k);
  }
  return { k1neg, k1, k2neg, k2 };
}
function validateSigFormat(format) {
  if (!["compact", "recovered", "der"].includes(format))
    throw new Error('Signature format must be "compact", "recovered", or "der"');
  return format;
}
function validateSigOpts(opts, def) {
  const optsn = {};
  for (let optName of Object.keys(def)) {
    optsn[optName] = opts[optName] === void 0 ? def[optName] : opts[optName];
  }
  _abool2(optsn.lowS, "lowS");
  _abool2(optsn.prehash, "prehash");
  if (optsn.format !== void 0)
    validateSigFormat(optsn.format);
  return optsn;
}
var DERErr = class extends Error {
  constructor(m = "") {
    super(m);
  }
};
var DER = {
  // asn.1 DER encoding utils
  Err: DERErr,
  // Basic building block is TLV (Tag-Length-Value)
  _tlv: {
    encode: (tag, data) => {
      const { Err: E } = DER;
      if (tag < 0 || tag > 256)
        throw new E("tlv.encode: wrong tag");
      if (data.length & 1)
        throw new E("tlv.encode: unpadded data");
      const dataLen = data.length / 2;
      const len = numberToHexUnpadded(dataLen);
      if (len.length / 2 & 128)
        throw new E("tlv.encode: long form length too big");
      const lenLen = dataLen > 127 ? numberToHexUnpadded(len.length / 2 | 128) : "";
      const t = numberToHexUnpadded(tag);
      return t + lenLen + len + data;
    },
    // v - value, l - left bytes (unparsed)
    decode(tag, data) {
      const { Err: E } = DER;
      let pos = 0;
      if (tag < 0 || tag > 256)
        throw new E("tlv.encode: wrong tag");
      if (data.length < 2 || data[pos++] !== tag)
        throw new E("tlv.decode: wrong tlv");
      const first = data[pos++];
      const isLong = !!(first & 128);
      let length = 0;
      if (!isLong)
        length = first;
      else {
        const lenLen = first & 127;
        if (!lenLen)
          throw new E("tlv.decode(long): indefinite length not supported");
        if (lenLen > 4)
          throw new E("tlv.decode(long): byte length is too big");
        const lengthBytes = data.subarray(pos, pos + lenLen);
        if (lengthBytes.length !== lenLen)
          throw new E("tlv.decode: length bytes not complete");
        if (lengthBytes[0] === 0)
          throw new E("tlv.decode(long): zero leftmost byte");
        for (const b of lengthBytes)
          length = length << 8 | b;
        pos += lenLen;
        if (length < 128)
          throw new E("tlv.decode(long): not minimal encoding");
      }
      const v = data.subarray(pos, pos + length);
      if (v.length !== length)
        throw new E("tlv.decode: wrong value length");
      return { v, l: data.subarray(pos + length) };
    }
  },
  // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
  // since we always use positive integers here. It must always be empty:
  // - add zero byte if exists
  // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
  _int: {
    encode(num) {
      const { Err: E } = DER;
      if (num < _0n6)
        throw new E("integer: negative integers are not allowed");
      let hex = numberToHexUnpadded(num);
      if (Number.parseInt(hex[0], 16) & 8)
        hex = "00" + hex;
      if (hex.length & 1)
        throw new E("unexpected DER parsing assertion: unpadded hex");
      return hex;
    },
    decode(data) {
      const { Err: E } = DER;
      if (data[0] & 128)
        throw new E("invalid signature integer: negative");
      if (data[0] === 0 && !(data[1] & 128))
        throw new E("invalid signature integer: unnecessary leading zero");
      return bytesToNumberBE(data);
    }
  },
  toSig(hex) {
    const { Err: E, _int: int, _tlv: tlv } = DER;
    const data = ensureBytes("signature", hex);
    const { v: seqBytes, l: seqLeftBytes } = tlv.decode(48, data);
    if (seqLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    const { v: rBytes, l: rLeftBytes } = tlv.decode(2, seqBytes);
    const { v: sBytes, l: sLeftBytes } = tlv.decode(2, rLeftBytes);
    if (sLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    return { r: int.decode(rBytes), s: int.decode(sBytes) };
  },
  hexFromSig(sig) {
    const { _tlv: tlv, _int: int } = DER;
    const rs = tlv.encode(2, int.encode(sig.r));
    const ss = tlv.encode(2, int.encode(sig.s));
    const seq = rs + ss;
    return tlv.encode(48, seq);
  }
};
var _0n6 = BigInt(0);
var _1n6 = BigInt(1);
var _2n4 = BigInt(2);
var _3n3 = BigInt(3);
var _4n2 = BigInt(4);
function _normFnElement(Fn2, key) {
  const { BYTES: expected } = Fn2;
  let num;
  if (typeof key === "bigint") {
    num = key;
  } else {
    let bytes = ensureBytes("private key", key);
    try {
      num = Fn2.fromBytes(bytes);
    } catch (error) {
      throw new Error(`invalid private key: expected ui8a of size ${expected}, got ${typeof key}`);
    }
  }
  if (!Fn2.isValidNot0(num))
    throw new Error("invalid private key: out of range [1..N-1]");
  return num;
}
function weierstrassN(params2, extraOpts = {}) {
  const validated = _createCurveFields("weierstrass", params2, extraOpts);
  const { Fp: Fp2, Fn: Fn2 } = validated;
  let CURVE = validated.CURVE;
  const { h: cofactor, n: CURVE_ORDER } = CURVE;
  _validateObject(extraOpts, {}, {
    allowInfinityPoint: "boolean",
    clearCofactor: "function",
    isTorsionFree: "function",
    fromBytes: "function",
    toBytes: "function",
    endo: "object",
    wrapPrivateKey: "boolean"
  });
  const { endo } = extraOpts;
  if (endo) {
    if (!Fp2.is0(CURVE.a) || typeof endo.beta !== "bigint" || !Array.isArray(endo.basises)) {
      throw new Error('invalid endo: expected "beta": bigint and "basises": array');
    }
  }
  const lengths = getWLengths(Fp2, Fn2);
  function assertCompressionIsSupported() {
    if (!Fp2.isOdd)
      throw new Error("compression is not supported: Field does not have .isOdd()");
  }
  function pointToBytes(_c, point, isCompressed) {
    const { x: x2, y } = point.toAffine();
    const bx = Fp2.toBytes(x2);
    _abool2(isCompressed, "isCompressed");
    if (isCompressed) {
      assertCompressionIsSupported();
      const hasEvenY = !Fp2.isOdd(y);
      return concatBytes(pprefix(hasEvenY), bx);
    } else {
      return concatBytes(Uint8Array.of(4), bx, Fp2.toBytes(y));
    }
  }
  function pointFromBytes(bytes) {
    _abytes2(bytes, void 0, "Point");
    const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths;
    const length = bytes.length;
    const head = bytes[0];
    const tail = bytes.subarray(1);
    if (length === comp && (head === 2 || head === 3)) {
      const x2 = Fp2.fromBytes(tail);
      if (!Fp2.isValid(x2))
        throw new Error("bad point: is not on curve, wrong x");
      const y2 = weierstrassEquation(x2);
      let y;
      try {
        y = Fp2.sqrt(y2);
      } catch (sqrtError) {
        const err2 = sqrtError instanceof Error ? ": " + sqrtError.message : "";
        throw new Error("bad point: is not on curve, sqrt error" + err2);
      }
      assertCompressionIsSupported();
      const isYOdd = Fp2.isOdd(y);
      const isHeadOdd = (head & 1) === 1;
      if (isHeadOdd !== isYOdd)
        y = Fp2.neg(y);
      return { x: x2, y };
    } else if (length === uncomp && head === 4) {
      const L = Fp2.BYTES;
      const x2 = Fp2.fromBytes(tail.subarray(0, L));
      const y = Fp2.fromBytes(tail.subarray(L, L * 2));
      if (!isValidXY(x2, y))
        throw new Error("bad point: is not on curve");
      return { x: x2, y };
    } else {
      throw new Error(`bad point: got length ${length}, expected compressed=${comp} or uncompressed=${uncomp}`);
    }
  }
  const encodePoint = extraOpts.toBytes || pointToBytes;
  const decodePoint = extraOpts.fromBytes || pointFromBytes;
  function weierstrassEquation(x2) {
    const x22 = Fp2.sqr(x2);
    const x3 = Fp2.mul(x22, x2);
    return Fp2.add(Fp2.add(x3, Fp2.mul(x2, CURVE.a)), CURVE.b);
  }
  function isValidXY(x2, y) {
    const left = Fp2.sqr(y);
    const right = weierstrassEquation(x2);
    return Fp2.eql(left, right);
  }
  if (!isValidXY(CURVE.Gx, CURVE.Gy))
    throw new Error("bad curve params: generator point");
  const _4a3 = Fp2.mul(Fp2.pow(CURVE.a, _3n3), _4n2);
  const _27b2 = Fp2.mul(Fp2.sqr(CURVE.b), BigInt(27));
  if (Fp2.is0(Fp2.add(_4a3, _27b2)))
    throw new Error("bad curve params: a or b");
  function acoord(title, n, banZero = false) {
    if (!Fp2.isValid(n) || banZero && Fp2.is0(n))
      throw new Error(`bad point coordinate ${title}`);
    return n;
  }
  function aprjpoint(other) {
    if (!(other instanceof Point))
      throw new Error("ProjectivePoint expected");
  }
  function splitEndoScalarN(k) {
    if (!endo || !endo.basises)
      throw new Error("no endo");
    return _splitEndoScalar(k, endo.basises, Fn2.ORDER);
  }
  const toAffineMemo = memoized((p, iz) => {
    const { X, Y, Z } = p;
    if (Fp2.eql(Z, Fp2.ONE))
      return { x: X, y: Y };
    const is0 = p.is0();
    if (iz == null)
      iz = is0 ? Fp2.ONE : Fp2.inv(Z);
    const x2 = Fp2.mul(X, iz);
    const y = Fp2.mul(Y, iz);
    const zz = Fp2.mul(Z, iz);
    if (is0)
      return { x: Fp2.ZERO, y: Fp2.ZERO };
    if (!Fp2.eql(zz, Fp2.ONE))
      throw new Error("invZ was invalid");
    return { x: x2, y };
  });
  const assertValidMemo = memoized((p) => {
    if (p.is0()) {
      if (extraOpts.allowInfinityPoint && !Fp2.is0(p.Y))
        return;
      throw new Error("bad point: ZERO");
    }
    const { x: x2, y } = p.toAffine();
    if (!Fp2.isValid(x2) || !Fp2.isValid(y))
      throw new Error("bad point: x or y not field elements");
    if (!isValidXY(x2, y))
      throw new Error("bad point: equation left != right");
    if (!p.isTorsionFree())
      throw new Error("bad point: not in prime-order subgroup");
    return true;
  });
  function finishEndo(endoBeta, k1p, k2p, k1neg, k2neg) {
    k2p = new Point(Fp2.mul(k2p.X, endoBeta), k2p.Y, k2p.Z);
    k1p = negateCt(k1neg, k1p);
    k2p = negateCt(k2neg, k2p);
    return k1p.add(k2p);
  }
  class Point {
    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    constructor(X, Y, Z) {
      this.X = acoord("x", X);
      this.Y = acoord("y", Y, true);
      this.Z = acoord("z", Z);
      Object.freeze(this);
    }
    static CURVE() {
      return CURVE;
    }
    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    static fromAffine(p) {
      const { x: x2, y } = p || {};
      if (!p || !Fp2.isValid(x2) || !Fp2.isValid(y))
        throw new Error("invalid affine point");
      if (p instanceof Point)
        throw new Error("projective point not allowed");
      if (Fp2.is0(x2) && Fp2.is0(y))
        return Point.ZERO;
      return new Point(x2, y, Fp2.ONE);
    }
    static fromBytes(bytes) {
      const P = Point.fromAffine(decodePoint(_abytes2(bytes, void 0, "point")));
      P.assertValidity();
      return P;
    }
    static fromHex(hex) {
      return Point.fromBytes(ensureBytes("pointHex", hex));
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    /**
     *
     * @param windowSize
     * @param isLazy true will defer table computation until the first multiplication
     * @returns
     */
    precompute(windowSize = 8, isLazy = true) {
      wnaf.createCache(this, windowSize);
      if (!isLazy)
        this.multiply(_3n3);
      return this;
    }
    // TODO: return `this`
    /** A point on curve is valid if it conforms to equation. */
    assertValidity() {
      assertValidMemo(this);
    }
    hasEvenY() {
      const { y } = this.toAffine();
      if (!Fp2.isOdd)
        throw new Error("Field doesn't support isOdd");
      return !Fp2.isOdd(y);
    }
    /** Compare one point to another. */
    equals(other) {
      aprjpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      const U1 = Fp2.eql(Fp2.mul(X1, Z2), Fp2.mul(X2, Z1));
      const U2 = Fp2.eql(Fp2.mul(Y1, Z2), Fp2.mul(Y2, Z1));
      return U1 && U2;
    }
    /** Flips point to one corresponding to (x, -y) in Affine coordinates. */
    negate() {
      return new Point(this.X, Fp2.neg(this.Y), this.Z);
    }
    // Renes-Costello-Batina exception-free doubling formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 3
    // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
    double() {
      const { a, b } = CURVE;
      const b3 = Fp2.mul(b, _3n3);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      let X3 = Fp2.ZERO, Y3 = Fp2.ZERO, Z3 = Fp2.ZERO;
      let t0 = Fp2.mul(X1, X1);
      let t1 = Fp2.mul(Y1, Y1);
      let t2 = Fp2.mul(Z1, Z1);
      let t3 = Fp2.mul(X1, Y1);
      t3 = Fp2.add(t3, t3);
      Z3 = Fp2.mul(X1, Z1);
      Z3 = Fp2.add(Z3, Z3);
      X3 = Fp2.mul(a, Z3);
      Y3 = Fp2.mul(b3, t2);
      Y3 = Fp2.add(X3, Y3);
      X3 = Fp2.sub(t1, Y3);
      Y3 = Fp2.add(t1, Y3);
      Y3 = Fp2.mul(X3, Y3);
      X3 = Fp2.mul(t3, X3);
      Z3 = Fp2.mul(b3, Z3);
      t2 = Fp2.mul(a, t2);
      t3 = Fp2.sub(t0, t2);
      t3 = Fp2.mul(a, t3);
      t3 = Fp2.add(t3, Z3);
      Z3 = Fp2.add(t0, t0);
      t0 = Fp2.add(Z3, t0);
      t0 = Fp2.add(t0, t2);
      t0 = Fp2.mul(t0, t3);
      Y3 = Fp2.add(Y3, t0);
      t2 = Fp2.mul(Y1, Z1);
      t2 = Fp2.add(t2, t2);
      t0 = Fp2.mul(t2, t3);
      X3 = Fp2.sub(X3, t0);
      Z3 = Fp2.mul(t2, t1);
      Z3 = Fp2.add(Z3, Z3);
      Z3 = Fp2.add(Z3, Z3);
      return new Point(X3, Y3, Z3);
    }
    // Renes-Costello-Batina exception-free addition formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 1
    // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
    add(other) {
      aprjpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      let X3 = Fp2.ZERO, Y3 = Fp2.ZERO, Z3 = Fp2.ZERO;
      const a = CURVE.a;
      const b3 = Fp2.mul(CURVE.b, _3n3);
      let t0 = Fp2.mul(X1, X2);
      let t1 = Fp2.mul(Y1, Y2);
      let t2 = Fp2.mul(Z1, Z2);
      let t3 = Fp2.add(X1, Y1);
      let t4 = Fp2.add(X2, Y2);
      t3 = Fp2.mul(t3, t4);
      t4 = Fp2.add(t0, t1);
      t3 = Fp2.sub(t3, t4);
      t4 = Fp2.add(X1, Z1);
      let t5 = Fp2.add(X2, Z2);
      t4 = Fp2.mul(t4, t5);
      t5 = Fp2.add(t0, t2);
      t4 = Fp2.sub(t4, t5);
      t5 = Fp2.add(Y1, Z1);
      X3 = Fp2.add(Y2, Z2);
      t5 = Fp2.mul(t5, X3);
      X3 = Fp2.add(t1, t2);
      t5 = Fp2.sub(t5, X3);
      Z3 = Fp2.mul(a, t4);
      X3 = Fp2.mul(b3, t2);
      Z3 = Fp2.add(X3, Z3);
      X3 = Fp2.sub(t1, Z3);
      Z3 = Fp2.add(t1, Z3);
      Y3 = Fp2.mul(X3, Z3);
      t1 = Fp2.add(t0, t0);
      t1 = Fp2.add(t1, t0);
      t2 = Fp2.mul(a, t2);
      t4 = Fp2.mul(b3, t4);
      t1 = Fp2.add(t1, t2);
      t2 = Fp2.sub(t0, t2);
      t2 = Fp2.mul(a, t2);
      t4 = Fp2.add(t4, t2);
      t0 = Fp2.mul(t1, t4);
      Y3 = Fp2.add(Y3, t0);
      t0 = Fp2.mul(t5, t4);
      X3 = Fp2.mul(t3, X3);
      X3 = Fp2.sub(X3, t0);
      t0 = Fp2.mul(t3, t1);
      Z3 = Fp2.mul(t5, Z3);
      Z3 = Fp2.add(Z3, t0);
      return new Point(X3, Y3, Z3);
    }
    subtract(other) {
      return this.add(other.negate());
    }
    is0() {
      return this.equals(Point.ZERO);
    }
    /**
     * Constant time multiplication.
     * Uses wNAF method. Windowed method may be 10% faster,
     * but takes 2x longer to generate and consumes 2x memory.
     * Uses precomputes when available.
     * Uses endomorphism for Koblitz curves.
     * @param scalar by which the point would be multiplied
     * @returns New point
     */
    multiply(scalar) {
      const { endo: endo2 } = extraOpts;
      if (!Fn2.isValidNot0(scalar))
        throw new Error("invalid scalar: out of range");
      let point, fake;
      const mul = (n) => wnaf.cached(this, n, (p) => normalizeZ(Point, p));
      if (endo2) {
        const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(scalar);
        const { p: k1p, f: k1f } = mul(k1);
        const { p: k2p, f: k2f } = mul(k2);
        fake = k1f.add(k2f);
        point = finishEndo(endo2.beta, k1p, k2p, k1neg, k2neg);
      } else {
        const { p, f } = mul(scalar);
        point = p;
        fake = f;
      }
      return normalizeZ(Point, [point, fake])[0];
    }
    /**
     * Non-constant-time multiplication. Uses double-and-add algorithm.
     * It's faster, but should only be used when you don't care about
     * an exposed secret key e.g. sig verification, which works over *public* keys.
     */
    multiplyUnsafe(sc) {
      const { endo: endo2 } = extraOpts;
      const p = this;
      if (!Fn2.isValid(sc))
        throw new Error("invalid scalar: out of range");
      if (sc === _0n6 || p.is0())
        return Point.ZERO;
      if (sc === _1n6)
        return p;
      if (wnaf.hasCache(this))
        return this.multiply(sc);
      if (endo2) {
        const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(sc);
        const { p1, p2 } = mulEndoUnsafe(Point, p, k1, k2);
        return finishEndo(endo2.beta, p1, p2, k1neg, k2neg);
      } else {
        return wnaf.unsafe(p, sc);
      }
    }
    multiplyAndAddUnsafe(Q2, a, b) {
      const sum = this.multiplyUnsafe(a).add(Q2.multiplyUnsafe(b));
      return sum.is0() ? void 0 : sum;
    }
    /**
     * Converts Projective point to affine (x, y) coordinates.
     * @param invertedZ Z^-1 (inverted zero) - optional, precomputation is useful for invertBatch
     */
    toAffine(invertedZ) {
      return toAffineMemo(this, invertedZ);
    }
    /**
     * Checks whether Point is free of torsion elements (is in prime subgroup).
     * Always torsion-free for cofactor=1 curves.
     */
    isTorsionFree() {
      const { isTorsionFree } = extraOpts;
      if (cofactor === _1n6)
        return true;
      if (isTorsionFree)
        return isTorsionFree(Point, this);
      return wnaf.unsafe(this, CURVE_ORDER).is0();
    }
    clearCofactor() {
      const { clearCofactor } = extraOpts;
      if (cofactor === _1n6)
        return this;
      if (clearCofactor)
        return clearCofactor(Point, this);
      return this.multiplyUnsafe(cofactor);
    }
    isSmallOrder() {
      return this.multiplyUnsafe(cofactor).is0();
    }
    toBytes(isCompressed = true) {
      _abool2(isCompressed, "isCompressed");
      this.assertValidity();
      return encodePoint(Point, this, isCompressed);
    }
    toHex(isCompressed = true) {
      return bytesToHex(this.toBytes(isCompressed));
    }
    toString() {
      return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
    }
    // TODO: remove
    get px() {
      return this.X;
    }
    get py() {
      return this.X;
    }
    get pz() {
      return this.Z;
    }
    toRawBytes(isCompressed = true) {
      return this.toBytes(isCompressed);
    }
    _setWindowSize(windowSize) {
      this.precompute(windowSize);
    }
    static normalizeZ(points) {
      return normalizeZ(Point, points);
    }
    static msm(points, scalars) {
      return pippenger(Point, Fn2, points, scalars);
    }
    static fromPrivateKey(privateKey) {
      return Point.BASE.multiply(_normFnElement(Fn2, privateKey));
    }
  }
  Point.BASE = new Point(CURVE.Gx, CURVE.Gy, Fp2.ONE);
  Point.ZERO = new Point(Fp2.ZERO, Fp2.ONE, Fp2.ZERO);
  Point.Fp = Fp2;
  Point.Fn = Fn2;
  const bits2 = Fn2.BITS;
  const wnaf = new wNAF(Point, extraOpts.endo ? Math.ceil(bits2 / 2) : bits2);
  Point.BASE.precompute(8);
  return Point;
}
function pprefix(hasEvenY) {
  return Uint8Array.of(hasEvenY ? 2 : 3);
}
function getWLengths(Fp2, Fn2) {
  return {
    secretKey: Fn2.BYTES,
    publicKey: 1 + Fp2.BYTES,
    publicKeyUncompressed: 1 + 2 * Fp2.BYTES,
    publicKeyHasPrefix: true,
    signature: 2 * Fn2.BYTES
  };
}
function ecdh(Point, ecdhOpts = {}) {
  const { Fn: Fn2 } = Point;
  const randomBytes_ = ecdhOpts.randomBytes || randomBytes;
  const lengths = Object.assign(getWLengths(Point.Fp, Fn2), { seed: getMinHashLength(Fn2.ORDER) });
  function isValidSecretKey(secretKey) {
    try {
      return !!_normFnElement(Fn2, secretKey);
    } catch (error) {
      return false;
    }
  }
  function isValidPublicKey(publicKey, isCompressed) {
    const { publicKey: comp, publicKeyUncompressed } = lengths;
    try {
      const l = publicKey.length;
      if (isCompressed === true && l !== comp)
        return false;
      if (isCompressed === false && l !== publicKeyUncompressed)
        return false;
      return !!Point.fromBytes(publicKey);
    } catch (error) {
      return false;
    }
  }
  function randomSecretKey(seed = randomBytes_(lengths.seed)) {
    return mapHashToField(_abytes2(seed, lengths.seed, "seed"), Fn2.ORDER);
  }
  function getPublicKey(secretKey, isCompressed = true) {
    return Point.BASE.multiply(_normFnElement(Fn2, secretKey)).toBytes(isCompressed);
  }
  function keygen(seed) {
    const secretKey = randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey(secretKey) };
  }
  function isProbPub(item) {
    if (typeof item === "bigint")
      return false;
    if (item instanceof Point)
      return true;
    const { secretKey, publicKey, publicKeyUncompressed } = lengths;
    if (Fn2.allowedLengths || secretKey === publicKey)
      return void 0;
    const l = ensureBytes("key", item).length;
    return l === publicKey || l === publicKeyUncompressed;
  }
  function getSharedSecret(secretKeyA, publicKeyB, isCompressed = true) {
    if (isProbPub(secretKeyA) === true)
      throw new Error("first arg must be private key");
    if (isProbPub(publicKeyB) === false)
      throw new Error("second arg must be public key");
    const s = _normFnElement(Fn2, secretKeyA);
    const b = Point.fromHex(publicKeyB);
    return b.multiply(s).toBytes(isCompressed);
  }
  const utils = {
    isValidSecretKey,
    isValidPublicKey,
    randomSecretKey,
    // TODO: remove
    isValidPrivateKey: isValidSecretKey,
    randomPrivateKey: randomSecretKey,
    normPrivateKeyToScalar: (key) => _normFnElement(Fn2, key),
    precompute(windowSize = 8, point = Point.BASE) {
      return point.precompute(windowSize, false);
    }
  };
  return Object.freeze({ getPublicKey, getSharedSecret, keygen, Point, utils, lengths });
}
function ecdsa(Point, hash, ecdsaOpts = {}) {
  ahash(hash);
  _validateObject(ecdsaOpts, {}, {
    hmac: "function",
    lowS: "boolean",
    randomBytes: "function",
    bits2int: "function",
    bits2int_modN: "function"
  });
  const randomBytes4 = ecdsaOpts.randomBytes || randomBytes;
  const hmac3 = ecdsaOpts.hmac || ((key, ...msgs) => hmac(hash, key, concatBytes(...msgs)));
  const { Fp: Fp2, Fn: Fn2 } = Point;
  const { ORDER: CURVE_ORDER, BITS: fnBits } = Fn2;
  const { keygen, getPublicKey, getSharedSecret, utils, lengths } = ecdh(Point, ecdsaOpts);
  const defaultSigOpts = {
    prehash: false,
    lowS: typeof ecdsaOpts.lowS === "boolean" ? ecdsaOpts.lowS : false,
    format: void 0,
    //'compact' as ECDSASigFormat,
    extraEntropy: false
  };
  const defaultSigOpts_format = "compact";
  function isBiggerThanHalfOrder(number) {
    const HALF = CURVE_ORDER >> _1n6;
    return number > HALF;
  }
  function validateRS(title, num) {
    if (!Fn2.isValidNot0(num))
      throw new Error(`invalid signature ${title}: out of range 1..Point.Fn.ORDER`);
    return num;
  }
  function validateSigLength(bytes, format) {
    validateSigFormat(format);
    const size = lengths.signature;
    const sizer = format === "compact" ? size : format === "recovered" ? size + 1 : void 0;
    return _abytes2(bytes, sizer, `${format} signature`);
  }
  class Signature {
    constructor(r, s, recovery) {
      this.r = validateRS("r", r);
      this.s = validateRS("s", s);
      if (recovery != null)
        this.recovery = recovery;
      Object.freeze(this);
    }
    static fromBytes(bytes, format = defaultSigOpts_format) {
      validateSigLength(bytes, format);
      let recid;
      if (format === "der") {
        const { r: r2, s: s2 } = DER.toSig(_abytes2(bytes));
        return new Signature(r2, s2);
      }
      if (format === "recovered") {
        recid = bytes[0];
        format = "compact";
        bytes = bytes.subarray(1);
      }
      const L = Fn2.BYTES;
      const r = bytes.subarray(0, L);
      const s = bytes.subarray(L, L * 2);
      return new Signature(Fn2.fromBytes(r), Fn2.fromBytes(s), recid);
    }
    static fromHex(hex, format) {
      return this.fromBytes(hexToBytes(hex), format);
    }
    addRecoveryBit(recovery) {
      return new Signature(this.r, this.s, recovery);
    }
    recoverPublicKey(messageHash) {
      const FIELD_ORDER = Fp2.ORDER;
      const { r, s, recovery: rec } = this;
      if (rec == null || ![0, 1, 2, 3].includes(rec))
        throw new Error("recovery id invalid");
      const hasCofactor = CURVE_ORDER * _2n4 < FIELD_ORDER;
      if (hasCofactor && rec > 1)
        throw new Error("recovery id is ambiguous for h>1 curve");
      const radj = rec === 2 || rec === 3 ? r + CURVE_ORDER : r;
      if (!Fp2.isValid(radj))
        throw new Error("recovery id 2 or 3 invalid");
      const x2 = Fp2.toBytes(radj);
      const R = Point.fromBytes(concatBytes(pprefix((rec & 1) === 0), x2));
      const ir = Fn2.inv(radj);
      const h = bits2int_modN(ensureBytes("msgHash", messageHash));
      const u1 = Fn2.create(-h * ir);
      const u2 = Fn2.create(s * ir);
      const Q2 = Point.BASE.multiplyUnsafe(u1).add(R.multiplyUnsafe(u2));
      if (Q2.is0())
        throw new Error("point at infinify");
      Q2.assertValidity();
      return Q2;
    }
    // Signatures should be low-s, to prevent malleability.
    hasHighS() {
      return isBiggerThanHalfOrder(this.s);
    }
    toBytes(format = defaultSigOpts_format) {
      validateSigFormat(format);
      if (format === "der")
        return hexToBytes(DER.hexFromSig(this));
      const r = Fn2.toBytes(this.r);
      const s = Fn2.toBytes(this.s);
      if (format === "recovered") {
        if (this.recovery == null)
          throw new Error("recovery bit must be present");
        return concatBytes(Uint8Array.of(this.recovery), r, s);
      }
      return concatBytes(r, s);
    }
    toHex(format) {
      return bytesToHex(this.toBytes(format));
    }
    // TODO: remove
    assertValidity() {
    }
    static fromCompact(hex) {
      return Signature.fromBytes(ensureBytes("sig", hex), "compact");
    }
    static fromDER(hex) {
      return Signature.fromBytes(ensureBytes("sig", hex), "der");
    }
    normalizeS() {
      return this.hasHighS() ? new Signature(this.r, Fn2.neg(this.s), this.recovery) : this;
    }
    toDERRawBytes() {
      return this.toBytes("der");
    }
    toDERHex() {
      return bytesToHex(this.toBytes("der"));
    }
    toCompactRawBytes() {
      return this.toBytes("compact");
    }
    toCompactHex() {
      return bytesToHex(this.toBytes("compact"));
    }
  }
  const bits2int = ecdsaOpts.bits2int || function bits2int_def(bytes) {
    if (bytes.length > 8192)
      throw new Error("input is too large");
    const num = bytesToNumberBE(bytes);
    const delta = bytes.length * 8 - fnBits;
    return delta > 0 ? num >> BigInt(delta) : num;
  };
  const bits2int_modN = ecdsaOpts.bits2int_modN || function bits2int_modN_def(bytes) {
    return Fn2.create(bits2int(bytes));
  };
  const ORDER_MASK = bitMask(fnBits);
  function int2octets(num) {
    aInRange("num < 2^" + fnBits, num, _0n6, ORDER_MASK);
    return Fn2.toBytes(num);
  }
  function validateMsgAndHash(message, prehash) {
    _abytes2(message, void 0, "message");
    return prehash ? _abytes2(hash(message), void 0, "prehashed message") : message;
  }
  function prepSig(message, privateKey, opts) {
    if (["recovered", "canonical"].some((k) => k in opts))
      throw new Error("sign() legacy options not supported");
    const { lowS, prehash, extraEntropy } = validateSigOpts(opts, defaultSigOpts);
    message = validateMsgAndHash(message, prehash);
    const h1int = bits2int_modN(message);
    const d = _normFnElement(Fn2, privateKey);
    const seedArgs = [int2octets(d), int2octets(h1int)];
    if (extraEntropy != null && extraEntropy !== false) {
      const e = extraEntropy === true ? randomBytes4(lengths.secretKey) : extraEntropy;
      seedArgs.push(ensureBytes("extraEntropy", e));
    }
    const seed = concatBytes(...seedArgs);
    const m = h1int;
    function k2sig(kBytes) {
      const k = bits2int(kBytes);
      if (!Fn2.isValidNot0(k))
        return;
      const ik = Fn2.inv(k);
      const q = Point.BASE.multiply(k).toAffine();
      const r = Fn2.create(q.x);
      if (r === _0n6)
        return;
      const s = Fn2.create(ik * Fn2.create(m + r * d));
      if (s === _0n6)
        return;
      let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n6);
      let normS = s;
      if (lowS && isBiggerThanHalfOrder(s)) {
        normS = Fn2.neg(s);
        recovery ^= 1;
      }
      return new Signature(r, normS, recovery);
    }
    return { seed, k2sig };
  }
  function sign(message, secretKey, opts = {}) {
    message = ensureBytes("message", message);
    const { seed, k2sig } = prepSig(message, secretKey, opts);
    const drbg = createHmacDrbg(hash.outputLen, Fn2.BYTES, hmac3);
    const sig = drbg(seed, k2sig);
    return sig;
  }
  function tryParsingSig(sg) {
    let sig = void 0;
    const isHex = typeof sg === "string" || isBytes(sg);
    const isObj = !isHex && sg !== null && typeof sg === "object" && typeof sg.r === "bigint" && typeof sg.s === "bigint";
    if (!isHex && !isObj)
      throw new Error("invalid signature, expected Uint8Array, hex string or Signature instance");
    if (isObj) {
      sig = new Signature(sg.r, sg.s);
    } else if (isHex) {
      try {
        sig = Signature.fromBytes(ensureBytes("sig", sg), "der");
      } catch (derError) {
        if (!(derError instanceof DER.Err))
          throw derError;
      }
      if (!sig) {
        try {
          sig = Signature.fromBytes(ensureBytes("sig", sg), "compact");
        } catch (error) {
          return false;
        }
      }
    }
    if (!sig)
      return false;
    return sig;
  }
  function verify2(signature, message, publicKey, opts = {}) {
    const { lowS, prehash, format } = validateSigOpts(opts, defaultSigOpts);
    publicKey = ensureBytes("publicKey", publicKey);
    message = validateMsgAndHash(ensureBytes("message", message), prehash);
    if ("strict" in opts)
      throw new Error("options.strict was renamed to lowS");
    const sig = format === void 0 ? tryParsingSig(signature) : Signature.fromBytes(ensureBytes("sig", signature), format);
    if (sig === false)
      return false;
    try {
      const P = Point.fromBytes(publicKey);
      if (lowS && sig.hasHighS())
        return false;
      const { r, s } = sig;
      const h = bits2int_modN(message);
      const is = Fn2.inv(s);
      const u1 = Fn2.create(h * is);
      const u2 = Fn2.create(r * is);
      const R = Point.BASE.multiplyUnsafe(u1).add(P.multiplyUnsafe(u2));
      if (R.is0())
        return false;
      const v = Fn2.create(R.x);
      return v === r;
    } catch (e) {
      return false;
    }
  }
  function recoverPublicKey(signature, message, opts = {}) {
    const { prehash } = validateSigOpts(opts, defaultSigOpts);
    message = validateMsgAndHash(message, prehash);
    return Signature.fromBytes(signature, "recovered").recoverPublicKey(message).toBytes();
  }
  return Object.freeze({
    keygen,
    getPublicKey,
    getSharedSecret,
    utils,
    lengths,
    Point,
    sign,
    verify: verify2,
    recoverPublicKey,
    Signature,
    hash
  });
}
function _weierstrass_legacy_opts_to_new(c) {
  const CURVE = {
    a: c.a,
    b: c.b,
    p: c.Fp.ORDER,
    n: c.n,
    h: c.h,
    Gx: c.Gx,
    Gy: c.Gy
  };
  const Fp2 = c.Fp;
  let allowedLengths = c.allowedPrivateKeyLengths ? Array.from(new Set(c.allowedPrivateKeyLengths.map((l) => Math.ceil(l / 2)))) : void 0;
  const Fn2 = Field(CURVE.n, {
    BITS: c.nBitLength,
    allowedLengths,
    modFromBytes: c.wrapPrivateKey
  });
  const curveOpts = {
    Fp: Fp2,
    Fn: Fn2,
    allowInfinityPoint: c.allowInfinityPoint,
    endo: c.endo,
    isTorsionFree: c.isTorsionFree,
    clearCofactor: c.clearCofactor,
    fromBytes: c.fromBytes,
    toBytes: c.toBytes
  };
  return { CURVE, curveOpts };
}
function _ecdsa_legacy_opts_to_new(c) {
  const { CURVE, curveOpts } = _weierstrass_legacy_opts_to_new(c);
  const ecdsaOpts = {
    hmac: c.hmac,
    randomBytes: c.randomBytes,
    lowS: c.lowS,
    bits2int: c.bits2int,
    bits2int_modN: c.bits2int_modN
  };
  return { CURVE, curveOpts, hash: c.hash, ecdsaOpts };
}
function _ecdsa_new_output_to_legacy(c, _ecdsa) {
  const Point = _ecdsa.Point;
  return Object.assign({}, _ecdsa, {
    ProjectivePoint: Point,
    CURVE: Object.assign({}, c, nLength(Point.Fn.ORDER, Point.Fn.BITS))
  });
}
function weierstrass(c) {
  const { CURVE, curveOpts, hash, ecdsaOpts } = _ecdsa_legacy_opts_to_new(c);
  const Point = weierstrassN(CURVE, curveOpts);
  const signs = ecdsa(Point, hash, ecdsaOpts);
  return _ecdsa_new_output_to_legacy(c, signs);
}

// node_modules/@noble/curves/esm/_shortw_utils.js
function createCurve(curveDef, defHash) {
  const create = (hash) => weierstrass({ ...curveDef, hash });
  return { ...create(defHash), create };
}

// node_modules/@noble/curves/esm/secp256k1.js
var secp256k1_CURVE = {
  p: BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
  n: BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
  h: BigInt(1),
  a: BigInt(0),
  b: BigInt(7),
  Gx: BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
  Gy: BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
};
var secp256k1_ENDO = {
  beta: BigInt("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"),
  basises: [
    [BigInt("0x3086d221a7d46bcde86c90e49284eb15"), -BigInt("0xe4437ed6010e88286f547fa90abfe4c3")],
    [BigInt("0x114ca50f7a8e2f3f657c1108d9d44cfd8"), BigInt("0x3086d221a7d46bcde86c90e49284eb15")]
  ]
};
var _2n5 = /* @__PURE__ */ BigInt(2);
function sqrtMod(y) {
  const P = secp256k1_CURVE.p;
  const _3n4 = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
  const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
  const b2 = y * y * y % P;
  const b3 = b2 * b2 * y % P;
  const b6 = pow2(b3, _3n4, P) * b3 % P;
  const b9 = pow2(b6, _3n4, P) * b3 % P;
  const b11 = pow2(b9, _2n5, P) * b2 % P;
  const b22 = pow2(b11, _11n, P) * b11 % P;
  const b44 = pow2(b22, _22n, P) * b22 % P;
  const b88 = pow2(b44, _44n, P) * b44 % P;
  const b176 = pow2(b88, _88n, P) * b88 % P;
  const b220 = pow2(b176, _44n, P) * b44 % P;
  const b223 = pow2(b220, _3n4, P) * b3 % P;
  const t1 = pow2(b223, _23n, P) * b22 % P;
  const t2 = pow2(t1, _6n, P) * b2 % P;
  const root = pow2(t2, _2n5, P);
  if (!Fpk1.eql(Fpk1.sqr(root), y))
    throw new Error("Cannot find square root");
  return root;
}
var Fpk1 = Field(secp256k1_CURVE.p, { sqrt: sqrtMod });
var secp256k1 = createCurve({ ...secp256k1_CURVE, Fp: Fpk1, lowS: true, endo: secp256k1_ENDO }, sha256);

// node_modules/@noble/post-quantum/node_modules/@noble/hashes/esm/_assert.js
function anumber2(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("positive integer expected, got " + n);
}
function isBytes2(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function abytes2(b, ...lengths) {
  if (!isBytes2(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function ahash2(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new Error("Hash should be wrapped by utils.wrapConstructor");
  anumber2(h.outputLen);
  anumber2(h.blockLen);
}
function aexists2(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput2(out, instance) {
  abytes2(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}

// node_modules/@noble/post-quantum/node_modules/@noble/hashes/esm/_u64.js
var U32_MASK642 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n2 = /* @__PURE__ */ BigInt(32);
function fromBig2(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK642), l: Number(n >> _32n2 & U32_MASK642) };
  return { h: Number(n >> _32n2 & U32_MASK642) | 0, l: Number(n & U32_MASK642) | 0 };
}
function split2(lst, le = false) {
  let Ah = new Uint32Array(lst.length);
  let Al = new Uint32Array(lst.length);
  for (let i2 = 0; i2 < lst.length; i2++) {
    const { h, l } = fromBig2(lst[i2], le);
    [Ah[i2], Al[i2]] = [h, l];
  }
  return [Ah, Al];
}
var toBig = (h, l) => BigInt(h >>> 0) << _32n2 | BigInt(l >>> 0);
var shrSH2 = (h, _l, s) => h >>> s;
var shrSL2 = (h, l, s) => h << 32 - s | l >>> s;
var rotrSH2 = (h, l, s) => h >>> s | l << 32 - s;
var rotrSL2 = (h, l, s) => h << 32 - s | l >>> s;
var rotrBH2 = (h, l, s) => h << 64 - s | l >>> s - 32;
var rotrBL2 = (h, l, s) => h >>> s - 32 | l << 64 - s;
var rotr32H = (_h, l) => l;
var rotr32L = (h, _l) => h;
var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;
function add2(Ah, Al, Bh, Bl) {
  const l = (Al >>> 0) + (Bl >>> 0);
  return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
}
var add3L2 = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
var add3H2 = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
var add4L2 = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
var add4H2 = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
var add5L2 = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
var add5H2 = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
var u64 = {
  fromBig: fromBig2,
  split: split2,
  toBig,
  shrSH: shrSH2,
  shrSL: shrSL2,
  rotrSH: rotrSH2,
  rotrSL: rotrSL2,
  rotrBH: rotrBH2,
  rotrBL: rotrBL2,
  rotr32H,
  rotr32L,
  rotlSH,
  rotlSL,
  rotlBH,
  rotlBL,
  add: add2,
  add3L: add3L2,
  add3H: add3H2,
  add4L: add4L2,
  add4H: add4H2,
  add5H: add5H2,
  add5L: add5L2
};
var u64_default = u64;

// node_modules/@noble/post-quantum/node_modules/@noble/hashes/esm/crypto.js
var crypto2 = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0;

// node_modules/@noble/post-quantum/node_modules/@noble/hashes/esm/utils.js
var u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
var createView2 = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
var rotr2 = (word, shift) => word << 32 - shift | word >>> shift;
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
var byteSwap = (word) => word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
function byteSwap32(arr) {
  for (let i2 = 0; i2 < arr.length; i2++) {
    arr[i2] = byteSwap(arr[i2]);
  }
}
var hexes2 = /* @__PURE__ */ Array.from({ length: 256 }, (_, i2) => i2.toString(16).padStart(2, "0"));
function bytesToHex2(bytes) {
  abytes2(bytes);
  let hex = "";
  for (let i2 = 0; i2 < bytes.length; i2++) {
    hex += hexes2[bytes[i2]];
  }
  return hex;
}
var asciis2 = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase162(ch) {
  if (ch >= asciis2._0 && ch <= asciis2._9)
    return ch - asciis2._0;
  if (ch >= asciis2.A && ch <= asciis2.F)
    return ch - (asciis2.A - 10);
  if (ch >= asciis2.a && ch <= asciis2.f)
    return ch - (asciis2.a - 10);
  return;
}
function hexToBytes2(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new Error("padded hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase162(hex.charCodeAt(hi));
    const n2 = asciiToBase162(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function utf8ToBytes2(str) {
  if (typeof str !== "string")
    throw new Error("utf8ToBytes expected string, got " + typeof str);
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes2(data) {
  if (typeof data === "string")
    data = utf8ToBytes2(data);
  abytes2(data);
  return data;
}
function concatBytes2(...arrays) {
  let sum = 0;
  for (let i2 = 0; i2 < arrays.length; i2++) {
    const a = arrays[i2];
    abytes2(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i2 = 0, pad = 0; i2 < arrays.length; i2++) {
    const a = arrays[i2];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
var Hash2 = class {
  // Safe version that clones internal state
  clone() {
    return this._cloneInto();
  }
};
function wrapConstructor(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes2(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
function wrapXOFConstructorWithOpts(hashCons) {
  const hashC = (msg, opts) => hashCons(opts).update(toBytes2(msg)).digest();
  const tmp = hashCons({});
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts) => hashCons(opts);
  return hashC;
}
function randomBytes2(bytesLength = 32) {
  if (crypto2 && typeof crypto2.getRandomValues === "function") {
    return crypto2.getRandomValues(new Uint8Array(bytesLength));
  }
  if (crypto2 && typeof crypto2.randomBytes === "function") {
    return crypto2.randomBytes(bytesLength);
  }
  throw new Error("crypto.getRandomValues must be defined");
}

// node_modules/@noble/post-quantum/node_modules/@noble/hashes/esm/sha3.js
var SHA3_PI = [];
var SHA3_ROTL = [];
var _SHA3_IOTA = [];
var _0n7 = /* @__PURE__ */ BigInt(0);
var _1n7 = /* @__PURE__ */ BigInt(1);
var _2n6 = /* @__PURE__ */ BigInt(2);
var _7n2 = /* @__PURE__ */ BigInt(7);
var _256n = /* @__PURE__ */ BigInt(256);
var _0x71n = /* @__PURE__ */ BigInt(113);
for (let round = 0, R = _1n7, x2 = 1, y = 0; round < 24; round++) {
  [x2, y] = [y, (2 * x2 + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x2));
  SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
  let t = _0n7;
  for (let j = 0; j < 7; j++) {
    R = (R << _1n7 ^ (R >> _7n2) * _0x71n) % _256n;
    if (R & _2n6)
      t ^= _1n7 << (_1n7 << /* @__PURE__ */ BigInt(j)) - _1n7;
  }
  _SHA3_IOTA.push(t);
}
var [SHA3_IOTA_H, SHA3_IOTA_L] = /* @__PURE__ */ split2(_SHA3_IOTA, true);
var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
function keccakP(s, rounds = 24) {
  const B = new Uint32Array(5 * 2);
  for (let round = 24 - rounds; round < 24; round++) {
    for (let x2 = 0; x2 < 10; x2++)
      B[x2] = s[x2] ^ s[x2 + 10] ^ s[x2 + 20] ^ s[x2 + 30] ^ s[x2 + 40];
    for (let x2 = 0; x2 < 10; x2 += 2) {
      const idx1 = (x2 + 8) % 10;
      const idx0 = (x2 + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0; y < 50; y += 10) {
        s[x2 + y] ^= Th;
        s[x2 + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0; t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0; y < 50; y += 10) {
      for (let x2 = 0; x2 < 10; x2++)
        B[x2] = s[y + x2];
      for (let x2 = 0; x2 < 10; x2++)
        s[y + x2] ^= ~B[(x2 + 2) % 10] & B[(x2 + 4) % 10];
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  B.fill(0);
}
var Keccak = class _Keccak extends Hash2 {
  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
    super();
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.rounds = rounds;
    this.pos = 0;
    this.posOut = 0;
    this.finished = false;
    this.destroyed = false;
    anumber2(outputLen);
    if (0 >= this.blockLen || this.blockLen >= 200)
      throw new Error("Sha3 supports only keccak-f1600 function");
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  keccak() {
    if (!isLE)
      byteSwap32(this.state32);
    keccakP(this.state32, this.rounds);
    if (!isLE)
      byteSwap32(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data) {
    aexists2(this);
    const { blockLen, state } = this;
    data = toBytes2(data);
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i2 = 0; i2 < take; i2++)
        state[this.pos++] ^= data[pos++];
      if (this.pos === blockLen)
        this.keccak();
    }
    return this;
  }
  finish() {
    if (this.finished)
      return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    state[pos] ^= suffix;
    if ((suffix & 128) !== 0 && pos === blockLen - 1)
      this.keccak();
    state[blockLen - 1] ^= 128;
    this.keccak();
  }
  writeInto(out) {
    aexists2(this, false);
    abytes2(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length; pos < len; ) {
      if (this.posOut >= blockLen)
        this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out) {
    if (!this.enableXOF)
      throw new Error("XOF is not possible for this instance");
    return this.writeInto(out);
  }
  xof(bytes) {
    anumber2(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }
  digestInto(out) {
    aoutput2(out, this);
    if (this.finished)
      throw new Error("digest() was already called");
    this.writeInto(out);
    this.destroy();
    return out;
  }
  digest() {
    return this.digestInto(new Uint8Array(this.outputLen));
  }
  destroy() {
    this.destroyed = true;
    this.state.fill(0);
  }
  _cloneInto(to) {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to || (to = new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds));
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.destroyed = this.destroyed;
    return to;
  }
};
var gen = (suffix, blockLen, outputLen) => wrapConstructor(() => new Keccak(blockLen, suffix, outputLen));
var sha3_224 = /* @__PURE__ */ gen(6, 144, 224 / 8);
var sha3_256 = /* @__PURE__ */ gen(6, 136, 256 / 8);
var sha3_384 = /* @__PURE__ */ gen(6, 104, 384 / 8);
var sha3_512 = /* @__PURE__ */ gen(6, 72, 512 / 8);
var keccak_224 = /* @__PURE__ */ gen(1, 144, 224 / 8);
var keccak_256 = /* @__PURE__ */ gen(1, 136, 256 / 8);
var keccak_384 = /* @__PURE__ */ gen(1, 104, 384 / 8);
var keccak_512 = /* @__PURE__ */ gen(1, 72, 512 / 8);
var genShake = (suffix, blockLen, outputLen) => wrapXOFConstructorWithOpts((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === void 0 ? outputLen : opts.dkLen, true));
var shake128 = /* @__PURE__ */ genShake(31, 168, 128 / 8);
var shake256 = /* @__PURE__ */ genShake(31, 136, 256 / 8);

// node_modules/@noble/post-quantum/esm/utils.js
var ensureBytes2 = abytes2;
var randomBytes3 = randomBytes2;
function equalBytes2(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i2 = 0; i2 < a.length; i2++)
    diff |= a[i2] ^ b[i2];
  return diff === 0;
}
function splitCoder(...lengths) {
  const getLength = (c) => typeof c === "number" ? c : c.bytesLen;
  const bytesLen = lengths.reduce((sum, a) => sum + getLength(a), 0);
  return {
    bytesLen,
    encode: (bufs) => {
      const res = new Uint8Array(bytesLen);
      for (let i2 = 0, pos = 0; i2 < lengths.length; i2++) {
        const c = lengths[i2];
        const l = getLength(c);
        const b = typeof c === "number" ? bufs[i2] : c.encode(bufs[i2]);
        ensureBytes2(b, l);
        res.set(b, pos);
        if (typeof c !== "number")
          b.fill(0);
        pos += l;
      }
      return res;
    },
    decode: (buf) => {
      ensureBytes2(buf, bytesLen);
      const res = [];
      for (const c of lengths) {
        const l = getLength(c);
        const b = buf.subarray(0, l);
        res.push(typeof c === "number" ? b : c.decode(b));
        buf = buf.subarray(l);
      }
      return res;
    }
  };
}
function vecCoder(c, vecLen) {
  const bytesLen = vecLen * c.bytesLen;
  return {
    bytesLen,
    encode: (u) => {
      if (u.length !== vecLen)
        throw new Error(`vecCoder.encode: wrong length=${u.length}. Expected: ${vecLen}`);
      const res = new Uint8Array(bytesLen);
      for (let i2 = 0, pos = 0; i2 < u.length; i2++) {
        const b = c.encode(u[i2]);
        res.set(b, pos);
        b.fill(0);
        pos += b.length;
      }
      return res;
    },
    decode: (a) => {
      ensureBytes2(a, bytesLen);
      const r = [];
      for (let i2 = 0; i2 < a.length; i2 += c.bytesLen)
        r.push(c.decode(a.subarray(i2, i2 + c.bytesLen)));
      return r;
    }
  };
}
function cleanBytes(...list) {
  for (const t of list) {
    if (Array.isArray(t))
      for (const b of t)
        b.fill(0);
    else
      t.fill(0);
  }
}
function getMask(bits2) {
  return (1 << bits2) - 1;
}

// node_modules/@noble/post-quantum/esm/_crystals.js
function bitReversal(n, bits2 = 8) {
  const padded = n.toString(2).padStart(8, "0");
  const sliced = padded.slice(-bits2).padStart(7, "0");
  const revrsd = sliced.split("").reverse().join("");
  return Number.parseInt(revrsd, 2);
}
var genCrystals = (opts) => {
  const { newPoly: newPoly2, N: N2, Q: Q2, F: F2, ROOT_OF_UNITY: ROOT_OF_UNITY2, brvBits, isKyber } = opts;
  const mod3 = (a, modulo = Q2) => {
    const result = a % modulo | 0;
    return (result >= 0 ? result | 0 : modulo + result | 0) | 0;
  };
  const smod2 = (a, modulo = Q2) => {
    const r = mod3(a, modulo) | 0;
    return (r > modulo >> 1 ? r - modulo | 0 : r) | 0;
  };
  function getZettas() {
    const out = newPoly2(N2);
    for (let i2 = 0; i2 < N2; i2++) {
      const b = bitReversal(i2, brvBits);
      const p = BigInt(ROOT_OF_UNITY2) ** BigInt(b) % BigInt(Q2);
      out[i2] = Number(p) | 0;
    }
    return out;
  }
  const nttZetas = getZettas();
  const LEN1 = isKyber ? 128 : N2;
  const LEN2 = isKyber ? 1 : 0;
  const NTT2 = {
    encode: (r) => {
      for (let k = 1, len = 128; len > LEN2; len >>= 1) {
        for (let start = 0; start < N2; start += 2 * len) {
          const zeta = nttZetas[k++];
          for (let j = start; j < start + len; j++) {
            const t = mod3(zeta * r[j + len]);
            r[j + len] = mod3(r[j] - t) | 0;
            r[j] = mod3(r[j] + t) | 0;
          }
        }
      }
      return r;
    },
    decode: (r) => {
      for (let k = LEN1 - 1, len = 1 + LEN2; len < LEN1 + LEN2; len <<= 1) {
        for (let start = 0; start < N2; start += 2 * len) {
          const zeta = nttZetas[k--];
          for (let j = start; j < start + len; j++) {
            const t = r[j];
            r[j] = mod3(t + r[j + len]);
            r[j + len] = mod3(zeta * (r[j + len] - t));
          }
        }
      }
      for (let i2 = 0; i2 < r.length; i2++)
        r[i2] = mod3(F2 * r[i2]);
      return r;
    }
  };
  const bitsCoder2 = (d, c) => {
    const mask = getMask(d);
    const bytesLen = d * (N2 / 8);
    return {
      bytesLen,
      encode: (poly) => {
        const r = new Uint8Array(bytesLen);
        for (let i2 = 0, buf = 0, bufLen = 0, pos = 0; i2 < poly.length; i2++) {
          buf |= (c.encode(poly[i2]) & mask) << bufLen;
          bufLen += d;
          for (; bufLen >= 8; bufLen -= 8, buf >>= 8)
            r[pos++] = buf & getMask(bufLen);
        }
        return r;
      },
      decode: (bytes) => {
        const r = newPoly2(N2);
        for (let i2 = 0, buf = 0, bufLen = 0, pos = 0; i2 < bytes.length; i2++) {
          buf |= bytes[i2] << bufLen;
          bufLen += 8;
          for (; bufLen >= d; bufLen -= d, buf >>= d)
            r[pos++] = c.decode(buf & mask);
        }
        return r;
      }
    };
  };
  return { mod: mod3, smod: smod2, nttZetas, NTT: NTT2, bitsCoder: bitsCoder2 };
};
var createXofShake = (shake) => (seed, blockLen) => {
  if (!blockLen)
    blockLen = shake.blockLen;
  const _seed = new Uint8Array(seed.length + 2);
  _seed.set(seed);
  const seedLen = seed.length;
  const buf = new Uint8Array(blockLen);
  let h = shake.create({});
  let calls = 0;
  let xofs = 0;
  return {
    stats: () => ({ calls, xofs }),
    get: (x2, y) => {
      _seed[seedLen + 0] = x2;
      _seed[seedLen + 1] = y;
      h.destroy();
      h = shake.create({}).update(_seed);
      calls++;
      return () => {
        xofs++;
        return h.xofInto(buf);
      };
    },
    clean: () => {
      h.destroy();
      buf.fill(0);
      _seed.fill(0);
    }
  };
};
var XOF128 = /* @__PURE__ */ createXofShake(shake128);
var XOF256 = /* @__PURE__ */ createXofShake(shake256);

// node_modules/@noble/post-quantum/esm/ml-dsa.js
var N = 256;
var Q = 8380417;
var ROOT_OF_UNITY = 1753;
var F = 8347681;
var D = 13;
var GAMMA2_1 = Math.floor((Q - 1) / 88) | 0;
var GAMMA2_2 = Math.floor((Q - 1) / 32) | 0;
var PARAMS = {
  2: { K: 4, L: 4, D, GAMMA1: 2 ** 17, GAMMA2: GAMMA2_1, TAU: 39, ETA: 2, OMEGA: 80 },
  3: { K: 6, L: 5, D, GAMMA1: 2 ** 19, GAMMA2: GAMMA2_2, TAU: 49, ETA: 4, OMEGA: 55 },
  5: { K: 8, L: 7, D, GAMMA1: 2 ** 19, GAMMA2: GAMMA2_2, TAU: 60, ETA: 2, OMEGA: 75 }
};
var newPoly = (n) => new Int32Array(n);
var { mod: mod2, smod, NTT, bitsCoder } = genCrystals({
  N,
  Q,
  F,
  ROOT_OF_UNITY,
  newPoly,
  isKyber: false,
  brvBits: 8
});
var id = (n) => n;
var polyCoder = (d, compress = id, verify2 = id) => bitsCoder(d, {
  encode: (i2) => compress(verify2(i2)),
  decode: (i2) => verify2(compress(i2))
});
var polyAdd = (a, b) => {
  for (let i2 = 0; i2 < a.length; i2++)
    a[i2] = mod2(a[i2] + b[i2]);
  return a;
};
var polySub = (a, b) => {
  for (let i2 = 0; i2 < a.length; i2++)
    a[i2] = mod2(a[i2] - b[i2]);
  return a;
};
var polyShiftl = (p) => {
  for (let i2 = 0; i2 < N; i2++)
    p[i2] <<= D;
  return p;
};
var polyChknorm = (p, B) => {
  for (let i2 = 0; i2 < N; i2++)
    if (Math.abs(smod(p[i2])) >= B)
      return true;
  return false;
};
var MultiplyNTTs = (a, b) => {
  const c = newPoly(N);
  for (let i2 = 0; i2 < a.length; i2++)
    c[i2] = mod2(a[i2] * b[i2]);
  return c;
};
function RejNTTPoly(xof) {
  const r = newPoly(N);
  for (let j = 0; j < N; ) {
    const b = xof();
    if (b.length % 3)
      throw new Error("RejNTTPoly: unaligned block");
    for (let i2 = 0; j < N && i2 <= b.length - 3; i2 += 3) {
      const t = (b[i2 + 0] | b[i2 + 1] << 8 | b[i2 + 2] << 16) & 8388607;
      if (t < Q)
        r[j++] = t;
    }
  }
  return r;
}
var EMPTY = new Uint8Array(0);
function getDilithium(opts) {
  const { K, L, GAMMA1, GAMMA2, TAU, ETA, OMEGA } = opts;
  const { CRH_BYTES, TR_BYTES, C_TILDE_BYTES, XOF128: XOF1282, XOF256: XOF2562 } = opts;
  if (![2, 4].includes(ETA))
    throw new Error("Wrong ETA");
  if (![1 << 17, 1 << 19].includes(GAMMA1))
    throw new Error("Wrong GAMMA1");
  if (![GAMMA2_1, GAMMA2_2].includes(GAMMA2))
    throw new Error("Wrong GAMMA2");
  const BETA = TAU * ETA;
  const decompose = (r) => {
    const rPlus = mod2(r);
    const r0 = smod(rPlus, 2 * GAMMA2) | 0;
    if (rPlus - r0 === Q - 1)
      return { r1: 0 | 0, r0: r0 - 1 | 0 };
    const r1 = Math.floor((rPlus - r0) / (2 * GAMMA2)) | 0;
    return { r1, r0 };
  };
  const HighBits = (r) => decompose(r).r1;
  const LowBits = (r) => decompose(r).r0;
  const MakeHint = (z, r) => {
    const res0 = z <= GAMMA2 || z > Q - GAMMA2 || z === Q - GAMMA2 && r === 0 ? 0 : 1;
    return res0;
  };
  const UseHint = (h, r) => {
    const m = Math.floor((Q - 1) / (2 * GAMMA2));
    const { r1, r0 } = decompose(r);
    if (h === 1)
      return r0 > 0 ? mod2(r1 + 1, m) | 0 : mod2(r1 - 1, m) | 0;
    return r1 | 0;
  };
  const Power2Round = (r) => {
    const rPlus = mod2(r);
    const r0 = smod(rPlus, 2 ** D) | 0;
    return { r1: Math.floor((rPlus - r0) / 2 ** D) | 0, r0 };
  };
  const hintCoder = {
    bytesLen: OMEGA + K,
    encode: (h) => {
      if (h === false)
        throw new Error("hint.encode: hint is false");
      const res = new Uint8Array(OMEGA + K);
      for (let i2 = 0, k = 0; i2 < K; i2++) {
        for (let j = 0; j < N; j++)
          if (h[i2][j] !== 0)
            res[k++] = j;
        res[OMEGA + i2] = k;
      }
      return res;
    },
    decode: (buf) => {
      const h = [];
      let k = 0;
      for (let i2 = 0; i2 < K; i2++) {
        const hi = newPoly(N);
        if (buf[OMEGA + i2] < k || buf[OMEGA + i2] > OMEGA)
          return false;
        for (let j = k; j < buf[OMEGA + i2]; j++) {
          if (j > k && buf[j] <= buf[j - 1])
            return false;
          hi[buf[j]] = 1;
        }
        k = buf[OMEGA + i2];
        h.push(hi);
      }
      for (let j = k; j < OMEGA; j++)
        if (buf[j] !== 0)
          return false;
      return h;
    }
  };
  const ETACoder = polyCoder(ETA === 2 ? 3 : 4, (i2) => ETA - i2, (i2) => {
    if (!(-ETA <= i2 && i2 <= ETA))
      throw new Error(`malformed key s1/s3 ${i2} outside of ETA range [${-ETA}, ${ETA}]`);
    return i2;
  });
  const T0Coder = polyCoder(13, (i2) => (1 << D - 1) - i2);
  const T1Coder = polyCoder(10);
  const ZCoder = polyCoder(GAMMA1 === 1 << 17 ? 18 : 20, (i2) => smod(GAMMA1 - i2));
  const W1Coder = polyCoder(GAMMA2 === GAMMA2_1 ? 6 : 4);
  const W1Vec = vecCoder(W1Coder, K);
  const publicCoder = splitCoder(32, vecCoder(T1Coder, K));
  const secretCoder = splitCoder(32, 32, TR_BYTES, vecCoder(ETACoder, L), vecCoder(ETACoder, K), vecCoder(T0Coder, K));
  const sigCoder = splitCoder(C_TILDE_BYTES, vecCoder(ZCoder, L), hintCoder);
  const CoefFromHalfByte = ETA === 2 ? (n) => n < 15 ? 2 - n % 5 : false : (n) => n < 9 ? 4 - n : false;
  function RejBoundedPoly(xof) {
    const r = newPoly(N);
    for (let j = 0; j < N; ) {
      const b = xof();
      for (let i2 = 0; j < N && i2 < b.length; i2 += 1) {
        const d1 = CoefFromHalfByte(b[i2] & 15);
        const d2 = CoefFromHalfByte(b[i2] >> 4 & 15);
        if (d1 !== false)
          r[j++] = d1;
        if (j < N && d2 !== false)
          r[j++] = d2;
      }
    }
    return r;
  }
  const SampleInBall = (seed) => {
    const pre = newPoly(N);
    const s = shake256.create({}).update(seed);
    const buf = new Uint8Array(shake256.blockLen);
    s.xofInto(buf);
    const masks = buf.slice(0, 8);
    for (let i2 = N - TAU, pos = 8, maskPos = 0, maskBit = 0; i2 < N; i2++) {
      let b = i2 + 1;
      for (; b > i2; ) {
        b = buf[pos++];
        if (pos < shake256.blockLen)
          continue;
        s.xofInto(buf);
        pos = 0;
      }
      pre[i2] = pre[b];
      pre[b] = 1 - ((masks[maskPos] >> maskBit++ & 1) << 1);
      if (maskBit >= 8) {
        maskPos++;
        maskBit = 0;
      }
    }
    return pre;
  };
  const polyPowerRound = (p) => {
    const res0 = newPoly(N);
    const res1 = newPoly(N);
    for (let i2 = 0; i2 < p.length; i2++) {
      const { r0, r1 } = Power2Round(p[i2]);
      res0[i2] = r0;
      res1[i2] = r1;
    }
    return { r0: res0, r1: res1 };
  };
  const polyUseHint = (u, h) => {
    for (let i2 = 0; i2 < N; i2++)
      u[i2] = UseHint(h[i2], u[i2]);
    return u;
  };
  const polyMakeHint = (a, b) => {
    const v = newPoly(N);
    let cnt = 0;
    for (let i2 = 0; i2 < N; i2++) {
      const h = MakeHint(a[i2], b[i2]);
      v[i2] = h;
      cnt += h;
    }
    return { v, cnt };
  };
  const signRandBytes = 32;
  const seedCoder = splitCoder(32, 64, 32);
  const internal = {
    signRandBytes,
    keygen: (seed = randomBytes3(32)) => {
      const seedDst = new Uint8Array(32 + 2);
      seedDst.set(seed);
      seedDst[32] = K;
      seedDst[33] = L;
      const [rho, rhoPrime, K_] = seedCoder.decode(shake256(seedDst, { dkLen: seedCoder.bytesLen }));
      const xofPrime = XOF2562(rhoPrime);
      const s1 = [];
      for (let i2 = 0; i2 < L; i2++)
        s1.push(RejBoundedPoly(xofPrime.get(i2 & 255, i2 >> 8 & 255)));
      const s2 = [];
      for (let i2 = L; i2 < L + K; i2++)
        s2.push(RejBoundedPoly(xofPrime.get(i2 & 255, i2 >> 8 & 255)));
      const s1Hat = s1.map((i2) => NTT.encode(i2.slice()));
      const t0 = [];
      const t1 = [];
      const xof = XOF1282(rho);
      const t = newPoly(N);
      for (let i2 = 0; i2 < K; i2++) {
        t.fill(0);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i2));
          polyAdd(t, MultiplyNTTs(aij, s1Hat[j]));
        }
        NTT.decode(t);
        const { r0, r1 } = polyPowerRound(polyAdd(t, s2[i2]));
        t0.push(r0);
        t1.push(r1);
      }
      const publicKey = publicCoder.encode([rho, t1]);
      const tr = shake256(publicKey, { dkLen: TR_BYTES });
      const secretKey = secretCoder.encode([rho, K_, tr, s1, s2, t0]);
      xof.clean();
      xofPrime.clean();
      cleanBytes(rho, rhoPrime, K_, s1, s2, s1Hat, t, t0, t1, tr, seedDst);
      return { publicKey, secretKey };
    },
    // NOTE: random is optional.
    sign: (secretKey, msg, random) => {
      const [rho, _K, tr, s1, s2, t0] = secretCoder.decode(secretKey);
      const A = [];
      const xof = XOF1282(rho);
      for (let i2 = 0; i2 < K; i2++) {
        const pv = [];
        for (let j = 0; j < L; j++)
          pv.push(RejNTTPoly(xof.get(j, i2)));
        A.push(pv);
      }
      xof.clean();
      for (let i2 = 0; i2 < L; i2++)
        NTT.encode(s1[i2]);
      for (let i2 = 0; i2 < K; i2++) {
        NTT.encode(s2[i2]);
        NTT.encode(t0[i2]);
      }
      const mu = shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest();
      const rnd = random ? random : new Uint8Array(32);
      ensureBytes2(rnd);
      const rhoprime = shake256.create({ dkLen: CRH_BYTES }).update(_K).update(rnd).update(mu).digest();
      ensureBytes2(rhoprime, CRH_BYTES);
      const x256 = XOF2562(rhoprime, ZCoder.bytesLen);
      main_loop: for (let kappa = 0; ; ) {
        const y = [];
        for (let i2 = 0; i2 < L; i2++, kappa++)
          y.push(ZCoder.decode(x256.get(kappa & 255, kappa >> 8)()));
        const z = y.map((i2) => NTT.encode(i2.slice()));
        const w = [];
        for (let i2 = 0; i2 < K; i2++) {
          const wi = newPoly(N);
          for (let j = 0; j < L; j++)
            polyAdd(wi, MultiplyNTTs(A[i2][j], z[j]));
          NTT.decode(wi);
          w.push(wi);
        }
        const w1 = w.map((j) => j.map(HighBits));
        const cTilde = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(w1)).digest();
        const cHat = NTT.encode(SampleInBall(cTilde));
        const cs1 = s1.map((i2) => MultiplyNTTs(i2, cHat));
        for (let i2 = 0; i2 < L; i2++) {
          polyAdd(NTT.decode(cs1[i2]), y[i2]);
          if (polyChknorm(cs1[i2], GAMMA1 - BETA))
            continue main_loop;
        }
        let cnt = 0;
        const h = [];
        for (let i2 = 0; i2 < K; i2++) {
          const cs2 = NTT.decode(MultiplyNTTs(s2[i2], cHat));
          const r0 = polySub(w[i2], cs2).map(LowBits);
          if (polyChknorm(r0, GAMMA2 - BETA))
            continue main_loop;
          const ct0 = NTT.decode(MultiplyNTTs(t0[i2], cHat));
          if (polyChknorm(ct0, GAMMA2))
            continue main_loop;
          polyAdd(r0, ct0);
          const hint = polyMakeHint(r0, w1[i2]);
          h.push(hint.v);
          cnt += hint.cnt;
        }
        if (cnt > OMEGA)
          continue;
        x256.clean();
        const res = sigCoder.encode([cTilde, cs1, h]);
        cleanBytes(cTilde, cs1, h, cHat, w1, w, z, y, rhoprime, mu, s1, s2, t0, ...A);
        return res;
      }
      throw new Error("Unreachable code path reached, report this error");
    },
    verify: (publicKey, msg, sig) => {
      const [rho, t1] = publicCoder.decode(publicKey);
      const tr = shake256(publicKey, { dkLen: TR_BYTES });
      if (sig.length !== sigCoder.bytesLen)
        return false;
      const [cTilde, z, h] = sigCoder.decode(sig);
      if (h === false)
        return false;
      for (let i2 = 0; i2 < L; i2++)
        if (polyChknorm(z[i2], GAMMA1 - BETA))
          return false;
      const mu = shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest();
      const c = NTT.encode(SampleInBall(cTilde));
      const zNtt = z.map((i2) => i2.slice());
      for (let i2 = 0; i2 < L; i2++)
        NTT.encode(zNtt[i2]);
      const wTick1 = [];
      const xof = XOF1282(rho);
      for (let i2 = 0; i2 < K; i2++) {
        const ct12d = MultiplyNTTs(NTT.encode(polyShiftl(t1[i2])), c);
        const Az = newPoly(N);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i2));
          polyAdd(Az, MultiplyNTTs(aij, zNtt[j]));
        }
        const wApprox = NTT.decode(polySub(Az, ct12d));
        wTick1.push(polyUseHint(wApprox, h[i2]));
      }
      xof.clean();
      const c2 = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(wTick1)).digest();
      for (const t of h) {
        const sum = t.reduce((acc, i2) => acc + i2, 0);
        if (!(sum <= OMEGA))
          return false;
      }
      for (const t of z)
        if (polyChknorm(t, GAMMA1 - BETA))
          return false;
      return equalBytes2(cTilde, c2);
    }
  };
  const getMessage = (msg, ctx = EMPTY) => {
    ensureBytes2(msg);
    ensureBytes2(ctx);
    if (ctx.length > 255)
      throw new Error("context should be less than 255 bytes");
    return concatBytes2(new Uint8Array([0, ctx.length]), ctx, msg);
  };
  return {
    internal,
    keygen: internal.keygen,
    signRandBytes: internal.signRandBytes,
    sign: (secretKey, msg, ctx = EMPTY, random) => {
      const M = getMessage(msg, ctx);
      const res = internal.sign(secretKey, M, random);
      M.fill(0);
      return res;
    },
    verify: (publicKey, msg, sig, ctx = EMPTY) => {
      return internal.verify(publicKey, getMessage(msg, ctx), sig);
    }
  };
}
var ml_dsa44 = /* @__PURE__ */ getDilithium({
  ...PARAMS[2],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 32,
  XOF128,
  XOF256
});
var ml_dsa65 = /* @__PURE__ */ getDilithium({
  ...PARAMS[3],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 48,
  XOF128,
  XOF256
});
var ml_dsa87 = /* @__PURE__ */ getDilithium({
  ...PARAMS[5],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 64,
  XOF128,
  XOF256
});

// node_modules/@noble/post-quantum/node_modules/@noble/hashes/esm/hmac.js
var HMAC2 = class extends Hash2 {
  constructor(hash, _key) {
    super();
    this.finished = false;
    this.destroyed = false;
    ahash2(hash);
    const key = toBytes2(_key);
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("Expected instance of class which extends utils.Hash");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i2 = 0; i2 < pad.length; i2++)
      pad[i2] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash.create();
    for (let i2 = 0; i2 < pad.length; i2++)
      pad[i2] ^= 54 ^ 92;
    this.oHash.update(pad);
    pad.fill(0);
  }
  update(buf) {
    aexists2(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    aexists2(this);
    abytes2(out, this.outputLen);
    this.finished = true;
    this.iHash.digestInto(out);
    this.oHash.update(out);
    this.oHash.digestInto(out);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to || (to = Object.create(Object.getPrototypeOf(this), {}));
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
};
var hmac2 = (hash, key, message) => new HMAC2(hash, key).update(message).digest();
hmac2.create = (hash, key) => new HMAC2(hash, key);

// node_modules/@noble/post-quantum/node_modules/@noble/hashes/esm/_md.js
function setBigUint642(view, byteOffset, value, isLE2) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE2);
  const _32n3 = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n3 & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE2 ? 4 : 0;
  const l = isLE2 ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE2);
  view.setUint32(byteOffset + l, wl, isLE2);
}
var Chi2 = (a, b, c) => a & b ^ ~a & c;
var Maj2 = (a, b, c) => a & b ^ a & c ^ b & c;
var HashMD2 = class extends Hash2 {
  constructor(blockLen, outputLen, padOffset, isLE2) {
    super();
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView2(this.buffer);
  }
  update(data) {
    aexists2(this);
    const { view, buffer, blockLen } = this;
    data = toBytes2(data);
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView2(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists2(this);
    aoutput2(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    this.buffer.subarray(pos).fill(0);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i2 = pos; i2 < blockLen; i2++)
      buffer[i2] = 0;
    setBigUint642(view, blockLen - 8, BigInt(this.length * 8), isLE2);
    this.process(view, 0);
    const oview = createView2(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i2 = 0; i2 < outLen; i2++)
      oview.setUint32(4 * i2, state[i2], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to || (to = new this.constructor());
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.length = length;
    to.pos = pos;
    to.finished = finished;
    to.destroyed = destroyed;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
};

// node_modules/@noble/post-quantum/node_modules/@noble/hashes/esm/sha256.js
var SHA256_K2 = /* @__PURE__ */ new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_IV2 = /* @__PURE__ */ new Uint32Array([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);
var SHA256_W2 = /* @__PURE__ */ new Uint32Array(64);
var SHA2562 = class extends HashMD2 {
  constructor() {
    super(64, 32, 8, false);
    this.A = SHA256_IV2[0] | 0;
    this.B = SHA256_IV2[1] | 0;
    this.C = SHA256_IV2[2] | 0;
    this.D = SHA256_IV2[3] | 0;
    this.E = SHA256_IV2[4] | 0;
    this.F = SHA256_IV2[5] | 0;
    this.G = SHA256_IV2[6] | 0;
    this.H = SHA256_IV2[7] | 0;
  }
  get() {
    const { A, B, C, D: D2, E, F: F2, G, H } = this;
    return [A, B, C, D2, E, F2, G, H];
  }
  // prettier-ignore
  set(A, B, C, D2, E, F2, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D2 | 0;
    this.E = E | 0;
    this.F = F2 | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i2 = 0; i2 < 16; i2++, offset += 4)
      SHA256_W2[i2] = view.getUint32(offset, false);
    for (let i2 = 16; i2 < 64; i2++) {
      const W15 = SHA256_W2[i2 - 15];
      const W2 = SHA256_W2[i2 - 2];
      const s0 = rotr2(W15, 7) ^ rotr2(W15, 18) ^ W15 >>> 3;
      const s1 = rotr2(W2, 17) ^ rotr2(W2, 19) ^ W2 >>> 10;
      SHA256_W2[i2] = s1 + SHA256_W2[i2 - 7] + s0 + SHA256_W2[i2 - 16] | 0;
    }
    let { A, B, C, D: D2, E, F: F2, G, H } = this;
    for (let i2 = 0; i2 < 64; i2++) {
      const sigma1 = rotr2(E, 6) ^ rotr2(E, 11) ^ rotr2(E, 25);
      const T1 = H + sigma1 + Chi2(E, F2, G) + SHA256_K2[i2] + SHA256_W2[i2] | 0;
      const sigma0 = rotr2(A, 2) ^ rotr2(A, 13) ^ rotr2(A, 22);
      const T2 = sigma0 + Maj2(A, B, C) | 0;
      H = G;
      G = F2;
      F2 = E;
      E = D2 + T1 | 0;
      D2 = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D2 = D2 + this.D | 0;
    E = E + this.E | 0;
    F2 = F2 + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D2, E, F2, G, H);
  }
  roundClean() {
    SHA256_W2.fill(0);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    this.buffer.fill(0);
  }
};
var sha2562 = /* @__PURE__ */ wrapConstructor(() => new SHA2562());

// node_modules/@noble/post-quantum/node_modules/@noble/hashes/esm/sha512.js
var [SHA512_Kh2, SHA512_Kl2] = /* @__PURE__ */ (() => u64_default.split([
  "0x428a2f98d728ae22",
  "0x7137449123ef65cd",
  "0xb5c0fbcfec4d3b2f",
  "0xe9b5dba58189dbbc",
  "0x3956c25bf348b538",
  "0x59f111f1b605d019",
  "0x923f82a4af194f9b",
  "0xab1c5ed5da6d8118",
  "0xd807aa98a3030242",
  "0x12835b0145706fbe",
  "0x243185be4ee4b28c",
  "0x550c7dc3d5ffb4e2",
  "0x72be5d74f27b896f",
  "0x80deb1fe3b1696b1",
  "0x9bdc06a725c71235",
  "0xc19bf174cf692694",
  "0xe49b69c19ef14ad2",
  "0xefbe4786384f25e3",
  "0x0fc19dc68b8cd5b5",
  "0x240ca1cc77ac9c65",
  "0x2de92c6f592b0275",
  "0x4a7484aa6ea6e483",
  "0x5cb0a9dcbd41fbd4",
  "0x76f988da831153b5",
  "0x983e5152ee66dfab",
  "0xa831c66d2db43210",
  "0xb00327c898fb213f",
  "0xbf597fc7beef0ee4",
  "0xc6e00bf33da88fc2",
  "0xd5a79147930aa725",
  "0x06ca6351e003826f",
  "0x142929670a0e6e70",
  "0x27b70a8546d22ffc",
  "0x2e1b21385c26c926",
  "0x4d2c6dfc5ac42aed",
  "0x53380d139d95b3df",
  "0x650a73548baf63de",
  "0x766a0abb3c77b2a8",
  "0x81c2c92e47edaee6",
  "0x92722c851482353b",
  "0xa2bfe8a14cf10364",
  "0xa81a664bbc423001",
  "0xc24b8b70d0f89791",
  "0xc76c51a30654be30",
  "0xd192e819d6ef5218",
  "0xd69906245565a910",
  "0xf40e35855771202a",
  "0x106aa07032bbd1b8",
  "0x19a4c116b8d2d0c8",
  "0x1e376c085141ab53",
  "0x2748774cdf8eeb99",
  "0x34b0bcb5e19b48a8",
  "0x391c0cb3c5c95a63",
  "0x4ed8aa4ae3418acb",
  "0x5b9cca4f7763e373",
  "0x682e6ff3d6b2b8a3",
  "0x748f82ee5defb2fc",
  "0x78a5636f43172f60",
  "0x84c87814a1f0ab72",
  "0x8cc702081a6439ec",
  "0x90befffa23631e28",
  "0xa4506cebde82bde9",
  "0xbef9a3f7b2c67915",
  "0xc67178f2e372532b",
  "0xca273eceea26619c",
  "0xd186b8c721c0c207",
  "0xeada7dd6cde0eb1e",
  "0xf57d4f7fee6ed178",
  "0x06f067aa72176fba",
  "0x0a637dc5a2c898a6",
  "0x113f9804bef90dae",
  "0x1b710b35131c471b",
  "0x28db77f523047d84",
  "0x32caab7b40c72493",
  "0x3c9ebe0a15c9bebc",
  "0x431d67c49c100d4c",
  "0x4cc5d4becb3e42b6",
  "0x597f299cfc657e2a",
  "0x5fcb6fab3ad6faec",
  "0x6c44198c4a475817"
].map((n) => BigInt(n))))();
var SHA512_W_H2 = /* @__PURE__ */ new Uint32Array(80);
var SHA512_W_L2 = /* @__PURE__ */ new Uint32Array(80);
var SHA5122 = class extends HashMD2 {
  constructor() {
    super(128, 64, 16, false);
    this.Ah = 1779033703 | 0;
    this.Al = 4089235720 | 0;
    this.Bh = 3144134277 | 0;
    this.Bl = 2227873595 | 0;
    this.Ch = 1013904242 | 0;
    this.Cl = 4271175723 | 0;
    this.Dh = 2773480762 | 0;
    this.Dl = 1595750129 | 0;
    this.Eh = 1359893119 | 0;
    this.El = 2917565137 | 0;
    this.Fh = 2600822924 | 0;
    this.Fl = 725511199 | 0;
    this.Gh = 528734635 | 0;
    this.Gl = 4215389547 | 0;
    this.Hh = 1541459225 | 0;
    this.Hl = 327033209 | 0;
  }
  // prettier-ignore
  get() {
    const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
  }
  // prettier-ignore
  set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
    this.Ah = Ah | 0;
    this.Al = Al | 0;
    this.Bh = Bh | 0;
    this.Bl = Bl | 0;
    this.Ch = Ch | 0;
    this.Cl = Cl | 0;
    this.Dh = Dh | 0;
    this.Dl = Dl | 0;
    this.Eh = Eh | 0;
    this.El = El | 0;
    this.Fh = Fh | 0;
    this.Fl = Fl | 0;
    this.Gh = Gh | 0;
    this.Gl = Gl | 0;
    this.Hh = Hh | 0;
    this.Hl = Hl | 0;
  }
  process(view, offset) {
    for (let i2 = 0; i2 < 16; i2++, offset += 4) {
      SHA512_W_H2[i2] = view.getUint32(offset);
      SHA512_W_L2[i2] = view.getUint32(offset += 4);
    }
    for (let i2 = 16; i2 < 80; i2++) {
      const W15h = SHA512_W_H2[i2 - 15] | 0;
      const W15l = SHA512_W_L2[i2 - 15] | 0;
      const s0h = u64_default.rotrSH(W15h, W15l, 1) ^ u64_default.rotrSH(W15h, W15l, 8) ^ u64_default.shrSH(W15h, W15l, 7);
      const s0l = u64_default.rotrSL(W15h, W15l, 1) ^ u64_default.rotrSL(W15h, W15l, 8) ^ u64_default.shrSL(W15h, W15l, 7);
      const W2h = SHA512_W_H2[i2 - 2] | 0;
      const W2l = SHA512_W_L2[i2 - 2] | 0;
      const s1h = u64_default.rotrSH(W2h, W2l, 19) ^ u64_default.rotrBH(W2h, W2l, 61) ^ u64_default.shrSH(W2h, W2l, 6);
      const s1l = u64_default.rotrSL(W2h, W2l, 19) ^ u64_default.rotrBL(W2h, W2l, 61) ^ u64_default.shrSL(W2h, W2l, 6);
      const SUMl = u64_default.add4L(s0l, s1l, SHA512_W_L2[i2 - 7], SHA512_W_L2[i2 - 16]);
      const SUMh = u64_default.add4H(SUMl, s0h, s1h, SHA512_W_H2[i2 - 7], SHA512_W_H2[i2 - 16]);
      SHA512_W_H2[i2] = SUMh | 0;
      SHA512_W_L2[i2] = SUMl | 0;
    }
    let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    for (let i2 = 0; i2 < 80; i2++) {
      const sigma1h = u64_default.rotrSH(Eh, El, 14) ^ u64_default.rotrSH(Eh, El, 18) ^ u64_default.rotrBH(Eh, El, 41);
      const sigma1l = u64_default.rotrSL(Eh, El, 14) ^ u64_default.rotrSL(Eh, El, 18) ^ u64_default.rotrBL(Eh, El, 41);
      const CHIh = Eh & Fh ^ ~Eh & Gh;
      const CHIl = El & Fl ^ ~El & Gl;
      const T1ll = u64_default.add5L(Hl, sigma1l, CHIl, SHA512_Kl2[i2], SHA512_W_L2[i2]);
      const T1h = u64_default.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh2[i2], SHA512_W_H2[i2]);
      const T1l = T1ll | 0;
      const sigma0h = u64_default.rotrSH(Ah, Al, 28) ^ u64_default.rotrBH(Ah, Al, 34) ^ u64_default.rotrBH(Ah, Al, 39);
      const sigma0l = u64_default.rotrSL(Ah, Al, 28) ^ u64_default.rotrBL(Ah, Al, 34) ^ u64_default.rotrBL(Ah, Al, 39);
      const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
      const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
      Hh = Gh | 0;
      Hl = Gl | 0;
      Gh = Fh | 0;
      Gl = Fl | 0;
      Fh = Eh | 0;
      Fl = El | 0;
      ({ h: Eh, l: El } = u64_default.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
      Dh = Ch | 0;
      Dl = Cl | 0;
      Ch = Bh | 0;
      Cl = Bl | 0;
      Bh = Ah | 0;
      Bl = Al | 0;
      const All = u64_default.add3L(T1l, sigma0l, MAJl);
      Ah = u64_default.add3H(All, T1h, sigma0h, MAJh);
      Al = All | 0;
    }
    ({ h: Ah, l: Al } = u64_default.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
    ({ h: Bh, l: Bl } = u64_default.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
    ({ h: Ch, l: Cl } = u64_default.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
    ({ h: Dh, l: Dl } = u64_default.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
    ({ h: Eh, l: El } = u64_default.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
    ({ h: Fh, l: Fl } = u64_default.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
    ({ h: Gh, l: Gl } = u64_default.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
    ({ h: Hh, l: Hl } = u64_default.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
    this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
  }
  roundClean() {
    SHA512_W_H2.fill(0);
    SHA512_W_L2.fill(0);
  }
  destroy() {
    this.buffer.fill(0);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
};
var sha5122 = /* @__PURE__ */ wrapConstructor(() => new SHA5122());

// node_modules/@noble/post-quantum/esm/slh-dsa.js
var PARAMS2 = {
  "128f": { W: 16, N: 16, H: 66, D: 22, K: 33, A: 6 },
  "128s": { W: 16, N: 16, H: 63, D: 7, K: 14, A: 12 },
  "192f": { W: 16, N: 24, H: 66, D: 22, K: 33, A: 8 },
  "192s": { W: 16, N: 24, H: 63, D: 7, K: 17, A: 14 },
  "256f": { W: 16, N: 32, H: 68, D: 17, K: 35, A: 9 },
  "256s": { W: 16, N: 32, H: 64, D: 8, K: 22, A: 14 }
};
function hexToNumber2(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  return BigInt(hex === "" ? "0" : "0x" + hex);
}
function bytesToNumberBE2(bytes) {
  return hexToNumber2(bytesToHex2(bytes));
}
function numberToBytesBE2(n, len) {
  return hexToBytes2(n.toString(16).padStart(len * 2, "0"));
}
var base2b = (outLen, b) => {
  const mask = getMask(b);
  return (bytes) => {
    const baseB = new Uint32Array(outLen);
    for (let out = 0, pos = 0, bits2 = 0, total = 0; out < outLen; out++) {
      while (bits2 < b) {
        total = total << 8 | bytes[pos++];
        bits2 += 8;
      }
      bits2 -= b;
      baseB[out] = total >>> bits2 & mask;
    }
    return baseB;
  };
};
function getMaskBig(bits2) {
  return (1n << BigInt(bits2)) - 1n;
}
function gen2(opts, hashOpts) {
  const { N: N2, W, H, D: D2, K, A } = opts;
  const getContext = hashOpts.getContext(opts);
  if (W !== 16)
    throw new Error("Unsupported Winternitz parameter");
  const WOTS_LOGW = 4;
  const WOTS_LEN1 = Math.floor(8 * N2 / WOTS_LOGW);
  const WOTS_LEN2 = N2 <= 8 ? 2 : N2 <= 136 ? 3 : 4;
  const TREE_HEIGHT = Math.floor(H / D2);
  const WOTS_LEN = WOTS_LEN1 + WOTS_LEN2;
  let ADDR_BYTES = 22;
  let OFFSET_LAYER = 0;
  let OFFSET_TREE = 1;
  let OFFSET_TYPE = 9;
  let OFFSET_KP_ADDR2 = 12;
  let OFFSET_KP_ADDR1 = 13;
  let OFFSET_CHAIN_ADDR = 17;
  let OFFSET_TREE_INDEX = 18;
  let OFFSET_HASH_ADDR = 21;
  if (!hashOpts.isCompressed) {
    ADDR_BYTES = 32;
    OFFSET_LAYER += 3;
    OFFSET_TREE += 7;
    OFFSET_TYPE += 10;
    OFFSET_KP_ADDR2 += 10;
    OFFSET_KP_ADDR1 += 10;
    OFFSET_CHAIN_ADDR += 10;
    OFFSET_TREE_INDEX += 10;
    OFFSET_HASH_ADDR += 10;
  }
  const setAddr = (opts2, addr = new Uint8Array(ADDR_BYTES)) => {
    const { type, height, tree, layer, index, chain, hash, keypair } = opts2;
    const { subtreeAddr, keypairAddr } = opts2;
    const v = createView2(addr);
    if (height !== void 0)
      addr[OFFSET_CHAIN_ADDR] = height;
    if (layer !== void 0)
      addr[OFFSET_LAYER] = layer;
    if (type !== void 0)
      addr[OFFSET_TYPE] = type;
    if (chain !== void 0)
      addr[OFFSET_CHAIN_ADDR] = chain;
    if (hash !== void 0)
      addr[OFFSET_HASH_ADDR] = hash;
    if (index !== void 0)
      v.setUint32(OFFSET_TREE_INDEX, index, false);
    if (subtreeAddr)
      addr.set(subtreeAddr.subarray(0, OFFSET_TREE + 8));
    if (tree !== void 0)
      v.setBigUint64(OFFSET_TREE, tree, false);
    if (keypair !== void 0) {
      addr[OFFSET_KP_ADDR1] = keypair;
      if (TREE_HEIGHT > 8)
        addr[OFFSET_KP_ADDR2] = keypair >>> 8;
    }
    if (keypairAddr) {
      addr.set(keypairAddr.subarray(0, OFFSET_TREE + 8));
      addr[OFFSET_KP_ADDR1] = keypairAddr[OFFSET_KP_ADDR1];
      if (TREE_HEIGHT > 8)
        addr[OFFSET_KP_ADDR2] = keypairAddr[OFFSET_KP_ADDR2];
    }
    return addr;
  };
  const chainCoder = base2b(WOTS_LEN2, WOTS_LOGW);
  const chainLengths = (msg) => {
    const W1 = base2b(WOTS_LEN1, WOTS_LOGW)(msg);
    let csum = 0;
    for (let i2 = 0; i2 < W1.length; i2++)
      csum += W - 1 - W1[i2];
    csum <<= (8 - WOTS_LEN2 * WOTS_LOGW % 8) % 8;
    const W2 = chainCoder(numberToBytesBE2(csum, Math.ceil(WOTS_LEN2 * WOTS_LOGW / 8)));
    const lengths = new Uint32Array(WOTS_LEN);
    lengths.set(W1);
    lengths.set(W2, W1.length);
    return lengths;
  };
  const messageToIndices = base2b(K, A);
  const TREE_BITS = TREE_HEIGHT * (D2 - 1);
  const LEAF_BITS = TREE_HEIGHT;
  const hashMsgCoder = splitCoder(Math.ceil(A * K / 8), Math.ceil(TREE_BITS / 8), Math.ceil(TREE_HEIGHT / 8));
  const hashMessage = (R, pkSeed, msg, context) => {
    const digest = context.Hmsg(R, pkSeed, msg, hashMsgCoder.bytesLen);
    const [md, tmpIdxTree, tmpIdxLeaf] = hashMsgCoder.decode(digest);
    const tree = bytesToNumberBE2(tmpIdxTree) & getMaskBig(TREE_BITS);
    const leafIdx = Number(bytesToNumberBE2(tmpIdxLeaf)) & getMask(LEAF_BITS);
    return { tree, leafIdx, md };
  };
  const treehash = (height, fn) => function treehash_i(context, leafIdx, idxOffset, treeAddr, info) {
    const maxIdx = (1 << height) - 1;
    const stack = new Uint8Array(height * N2);
    const authPath = new Uint8Array(height * N2);
    for (let idx = 0; ; idx++) {
      const current = new Uint8Array(2 * N2);
      const cur0 = current.subarray(0, N2);
      const cur1 = current.subarray(N2);
      const addrOffset = idx + idxOffset;
      cur1.set(fn(leafIdx, addrOffset, context, info));
      let h = 0;
      for (let i2 = idx, o = idxOffset, l = leafIdx; ; h++, i2 >>>= 1, l >>>= 1, o >>>= 1) {
        if (h === height)
          return { root: cur1, authPath };
        if ((i2 ^ l) === 1)
          authPath.subarray(h * N2).set(cur1);
        if ((i2 & 1) === 0 && idx < maxIdx)
          break;
        setAddr({ height: h + 1, index: (i2 >> 1) + (o >> 1) }, treeAddr);
        cur0.set(stack.subarray(h * N2).subarray(0, N2));
        cur1.set(context.thashN(2, current, treeAddr));
      }
      stack.subarray(h * N2).set(cur1);
    }
    throw new Error("Unreachable code path reached, report this error");
  };
  const wotsTreehash = treehash(TREE_HEIGHT, (leafIdx, addrOffset, context, info) => {
    const wotsPk = new Uint8Array(WOTS_LEN * N2);
    const wotsKmask = addrOffset === leafIdx ? 0 : ~0 >>> 0;
    setAddr({ keypair: addrOffset }, info.leafAddr);
    setAddr({ keypair: addrOffset }, info.pkAddr);
    for (let i2 = 0; i2 < WOTS_LEN; i2++) {
      const wotsK = info.wotsSteps[i2] | wotsKmask;
      const pk = wotsPk.subarray(i2 * N2, (i2 + 1) * N2);
      setAddr({
        chain: i2,
        hash: 0,
        type: 5
        /* AddressType.WOTSPRF */
      }, info.leafAddr);
      pk.set(context.PRFaddr(info.leafAddr));
      setAddr({
        type: 0
        /* AddressType.WOTS */
      }, info.leafAddr);
      for (let k = 0; ; k++) {
        if (k === wotsK)
          info.wotsSig.subarray(i2 * N2).set(pk);
        if (k === W - 1)
          break;
        setAddr({ hash: k }, info.leafAddr);
        pk.set(context.thash1(pk, info.leafAddr));
      }
    }
    return context.thashN(WOTS_LEN, wotsPk, info.pkAddr);
  });
  const forsTreehash = treehash(A, (_, addrOffset, context, forsLeafAddr) => {
    setAddr({ type: 6, index: addrOffset }, forsLeafAddr);
    const prf = context.PRFaddr(forsLeafAddr);
    setAddr({
      type: 3
      /* AddressType.FORSTREE */
    }, forsLeafAddr);
    return context.thash1(prf, forsLeafAddr);
  });
  const merkleSign = (context, wotsAddr, treeAddr, leafIdx, prevRoot = new Uint8Array(N2)) => {
    setAddr({
      type: 2
      /* AddressType.HASHTREE */
    }, treeAddr);
    const info = {
      wotsSig: new Uint8Array(wotsCoder.bytesLen),
      wotsSteps: chainLengths(prevRoot),
      leafAddr: setAddr({ subtreeAddr: wotsAddr }),
      pkAddr: setAddr({ type: 1, subtreeAddr: wotsAddr })
    };
    const { root, authPath } = wotsTreehash(context, leafIdx, 0, treeAddr, info);
    return {
      root,
      sigWots: info.wotsSig.subarray(0, WOTS_LEN * N2),
      sigAuth: authPath
    };
  };
  const computeRoot = (leaf, leafIdx, idxOffset, authPath, treeHeight, context, addr) => {
    const buffer = new Uint8Array(2 * N2);
    const b0 = buffer.subarray(0, N2);
    const b1 = buffer.subarray(N2, 2 * N2);
    if ((leafIdx & 1) !== 0) {
      b1.set(leaf.subarray(0, N2));
      b0.set(authPath.subarray(0, N2));
    } else {
      b0.set(leaf.subarray(0, N2));
      b1.set(authPath.subarray(0, N2));
    }
    leafIdx >>>= 1;
    idxOffset >>>= 1;
    for (let i2 = 0; i2 < treeHeight - 1; i2++, leafIdx >>= 1, idxOffset >>= 1) {
      setAddr({ height: i2 + 1, index: leafIdx + idxOffset }, addr);
      const a = authPath.subarray((i2 + 1) * N2, (i2 + 2) * N2);
      if ((leafIdx & 1) !== 0) {
        b1.set(context.thashN(2, buffer, addr));
        b0.set(a);
      } else {
        buffer.set(context.thashN(2, buffer, addr));
        b1.set(a);
      }
    }
    setAddr({ height: treeHeight, index: leafIdx + idxOffset }, addr);
    return context.thashN(2, buffer, addr);
  };
  const seedCoder = splitCoder(N2, N2, N2);
  const publicCoder = splitCoder(N2, N2);
  const secretCoder = splitCoder(N2, N2, publicCoder.bytesLen);
  const forsCoder = vecCoder(splitCoder(N2, N2 * A), K);
  const wotsCoder = vecCoder(splitCoder(WOTS_LEN * N2, TREE_HEIGHT * N2), D2);
  const sigCoder = splitCoder(N2, forsCoder, wotsCoder);
  return {
    seedLen: seedCoder.bytesLen,
    signRandBytes: N2,
    keygen(seed = randomBytes3(seedCoder.bytesLen)) {
      const [secretSeed, secretPRF, publicSeed] = seedCoder.decode(seed);
      const context = getContext(publicSeed, secretSeed);
      const topTreeAddr = setAddr({ layer: D2 - 1 });
      const wotsAddr = setAddr({ layer: D2 - 1 });
      const { root } = merkleSign(context, wotsAddr, topTreeAddr, ~0 >>> 0);
      const publicKey = publicCoder.encode([publicSeed, root]);
      const secretKey = secretCoder.encode([secretSeed, secretPRF, publicKey]);
      context.clean();
      cleanBytes(secretSeed, secretPRF, root, wotsAddr, topTreeAddr);
      return { publicKey, secretKey };
    },
    sign: (sk, msg, random) => {
      const [skSeed, skPRF, pk] = secretCoder.decode(sk);
      const [pkSeed, _] = publicCoder.decode(pk);
      if (!random)
        random = pkSeed.slice();
      ensureBytes2(random, N2);
      const context = getContext(pkSeed, skSeed);
      const R = context.PRFmsg(skPRF, random, msg);
      let { tree, leafIdx, md } = hashMessage(R, pk, msg, context);
      const wotsAddr = setAddr({
        type: 0,
        tree,
        keypair: leafIdx
      });
      const roots = [];
      const forsLeaf = setAddr({ keypairAddr: wotsAddr });
      const forsTreeAddr = setAddr({ keypairAddr: wotsAddr });
      const indices = messageToIndices(md);
      const fors = [];
      for (let i2 = 0; i2 < indices.length; i2++) {
        const idxOffset = i2 << A;
        setAddr({
          type: 6,
          height: 0,
          index: indices[i2] + idxOffset
        }, forsTreeAddr);
        const prf = context.PRFaddr(forsTreeAddr);
        setAddr({
          type: 3
          /* AddressType.FORSTREE */
        }, forsTreeAddr);
        const { root: root2, authPath } = forsTreehash(context, indices[i2], idxOffset, forsTreeAddr, forsLeaf);
        roots.push(root2);
        fors.push([prf, authPath]);
      }
      const forsPkAddr = setAddr({
        type: 4,
        keypairAddr: wotsAddr
      });
      const root = context.thashN(K, concatBytes2(...roots), forsPkAddr);
      const treeAddr = setAddr({
        type: 2
        /* AddressType.HASHTREE */
      });
      const wots = [];
      for (let i2 = 0; i2 < D2; i2++, tree >>= BigInt(TREE_HEIGHT)) {
        setAddr({ tree, layer: i2 }, treeAddr);
        setAddr({ subtreeAddr: treeAddr, keypair: leafIdx }, wotsAddr);
        const { sigWots, sigAuth, root: r } = merkleSign(context, wotsAddr, treeAddr, leafIdx, root);
        root.set(r);
        r.fill(0);
        wots.push([sigWots, sigAuth]);
        leafIdx = Number(tree & getMaskBig(TREE_HEIGHT));
      }
      context.clean();
      const SIG = sigCoder.encode([R, fors, wots]);
      cleanBytes(R, random, treeAddr, wotsAddr, forsLeaf, forsTreeAddr, indices, roots);
      return SIG;
    },
    verify: (publicKey, msg, sig) => {
      const [pkSeed, pubRoot] = publicCoder.decode(publicKey);
      const [random, forsVec, wotsVec] = sigCoder.decode(sig);
      const pk = publicKey;
      if (sig.length !== sigCoder.bytesLen)
        return false;
      const context = getContext(pkSeed);
      let { tree, leafIdx, md } = hashMessage(random, pk, msg, context);
      const wotsAddr = setAddr({
        type: 0,
        tree,
        keypair: leafIdx
      });
      const roots = [];
      const forsTreeAddr = setAddr({
        type: 3,
        keypairAddr: wotsAddr
      });
      const indices = messageToIndices(md);
      for (let i2 = 0; i2 < forsVec.length; i2++) {
        const [prf, authPath] = forsVec[i2];
        const idxOffset = i2 << A;
        setAddr({ height: 0, index: indices[i2] + idxOffset }, forsTreeAddr);
        const leaf = context.thash1(prf, forsTreeAddr);
        roots.push(computeRoot(leaf, indices[i2], idxOffset, authPath, A, context, forsTreeAddr));
      }
      const forsPkAddr = setAddr({
        type: 4,
        keypairAddr: wotsAddr
      });
      let root = context.thashN(K, concatBytes2(...roots), forsPkAddr);
      const treeAddr = setAddr({
        type: 2
        /* AddressType.HASHTREE */
      });
      const wotsPkAddr = setAddr({
        type: 1
        /* AddressType.WOTSPK */
      });
      const wotsPk = new Uint8Array(WOTS_LEN * N2);
      for (let i2 = 0; i2 < wotsVec.length; i2++, tree >>= BigInt(TREE_HEIGHT)) {
        const [wots, sigAuth] = wotsVec[i2];
        setAddr({ tree, layer: i2 }, treeAddr);
        setAddr({ subtreeAddr: treeAddr, keypair: leafIdx }, wotsAddr);
        setAddr({ keypairAddr: wotsAddr }, wotsPkAddr);
        const lengths = chainLengths(root);
        for (let i3 = 0; i3 < WOTS_LEN; i3++) {
          setAddr({ chain: i3 }, wotsAddr);
          const steps = W - 1 - lengths[i3];
          const start = lengths[i3];
          const out = wotsPk.subarray(i3 * N2);
          out.set(wots.subarray(i3 * N2, (i3 + 1) * N2));
          for (let j = start; j < start + steps && j < W; j++) {
            setAddr({ hash: j }, wotsAddr);
            out.set(context.thash1(out, wotsAddr));
          }
        }
        const leaf = context.thashN(WOTS_LEN, wotsPk, wotsPkAddr);
        root = computeRoot(leaf, leafIdx, 0, sigAuth, TREE_HEIGHT, context, treeAddr);
        leafIdx = Number(tree & getMaskBig(TREE_HEIGHT));
      }
      return equalBytes2(root, pubRoot);
    }
  };
}
var genShake2 = () => (opts) => (pubSeed, skSeed) => {
  const { N: N2 } = opts;
  const stats = { prf: 0, thash: 0, hmsg: 0, gen_message_random: 0 };
  const h0 = shake256.create({}).update(pubSeed);
  const h0tmp = h0.clone();
  const thash = (blocks, input, addr) => {
    stats.thash++;
    return h0._cloneInto(h0tmp).update(addr).update(input.subarray(0, blocks * N2)).xof(N2);
  };
  return {
    PRFaddr: (addr) => {
      if (!skSeed)
        throw new Error("no sk seed");
      stats.prf++;
      const res = h0._cloneInto(h0tmp).update(addr).update(skSeed).xof(N2);
      return res;
    },
    PRFmsg: (skPRF, random, msg) => {
      stats.gen_message_random++;
      return shake256.create({}).update(skPRF).update(random).update(msg).digest().subarray(0, N2);
    },
    Hmsg: (R, pk, m, outLen) => {
      stats.hmsg++;
      return shake256.create({}).update(R.subarray(0, N2)).update(pk).update(m).xof(outLen);
    },
    thash1: thash.bind(null, 1),
    thashN: thash,
    clean: () => {
      h0.destroy();
      h0tmp.destroy();
    }
  };
};
var SHAKE_SIMPLE = { getContext: genShake2() };
var slh_dsa_shake_128f = /* @__PURE__ */ gen2(PARAMS2["128f"], SHAKE_SIMPLE);
var slh_dsa_shake_128s = /* @__PURE__ */ gen2(PARAMS2["128s"], SHAKE_SIMPLE);
var slh_dsa_shake_192f = /* @__PURE__ */ gen2(PARAMS2["192f"], SHAKE_SIMPLE);
var slh_dsa_shake_192s = /* @__PURE__ */ gen2(PARAMS2["192s"], SHAKE_SIMPLE);
var slh_dsa_shake_256f = /* @__PURE__ */ gen2(PARAMS2["256f"], SHAKE_SIMPLE);
var slh_dsa_shake_256s = /* @__PURE__ */ gen2(PARAMS2["256s"], SHAKE_SIMPLE);
var genSha = (h0, h1) => (opts) => (pub_seed, sk_seed) => {
  const { N: N2 } = opts;
  const stats = { prf: 0, thash: 0, hmsg: 0, gen_message_random: 0, mgf1: 0 };
  const counterB = new Uint8Array(4);
  const counterV = createView2(counterB);
  const h0ps = h0.create().update(pub_seed).update(new Uint8Array(h0.blockLen - N2));
  const h1ps = h1.create().update(pub_seed).update(new Uint8Array(h1.blockLen - N2));
  const h0tmp = h0ps.clone();
  const h1tmp = h1ps.clone();
  function mgf1(seed, length, hash) {
    stats.mgf1++;
    const out = new Uint8Array(Math.ceil(length / hash.outputLen) * hash.outputLen);
    if (length > 2 ** 32)
      throw new Error("mask too long");
    for (let counter = 0, o = out; o.length; counter++) {
      counterV.setUint32(0, counter, false);
      hash.create().update(seed).update(counterB).digestInto(o);
      o = o.subarray(hash.outputLen);
    }
    out.subarray(length).fill(0);
    return out.subarray(0, length);
  }
  const thash = (_, h, hTmp) => (blocks, input, addr) => {
    stats.thash++;
    const d = h._cloneInto(hTmp).update(addr).update(input.subarray(0, blocks * N2)).digest();
    return d.subarray(0, N2);
  };
  return {
    PRFaddr: (addr) => {
      if (!sk_seed)
        throw new Error("No sk seed");
      stats.prf++;
      const res = h0ps._cloneInto(h0tmp).update(addr).update(sk_seed).digest().subarray(0, N2);
      return res;
    },
    PRFmsg: (skPRF, random, msg) => {
      stats.gen_message_random++;
      return new HMAC2(h1, skPRF).update(random).update(msg).digest().subarray(0, N2);
    },
    Hmsg: (R, pk, m, outLen) => {
      stats.hmsg++;
      const seed = concatBytes2(R.subarray(0, N2), pk.subarray(0, N2), h1.create().update(R.subarray(0, N2)).update(pk).update(m).digest());
      return mgf1(seed, outLen, h1);
    },
    thash1: thash(h0, h0ps, h0tmp).bind(null, 1),
    thashN: thash(h1, h1ps, h1tmp),
    clean: () => {
      h0ps.destroy();
      h1ps.destroy();
      h0tmp.destroy();
      h1tmp.destroy();
    }
  };
};
var SHA256_SIMPLE = {
  isCompressed: true,
  getContext: genSha(sha2562, sha2562)
};
var SHA512_SIMPLE = {
  isCompressed: true,
  getContext: genSha(sha2562, sha5122)
};
var slh_dsa_sha2_128f = /* @__PURE__ */ gen2(PARAMS2["128f"], SHA256_SIMPLE);
var slh_dsa_sha2_128s = /* @__PURE__ */ gen2(PARAMS2["128s"], SHA256_SIMPLE);
var slh_dsa_sha2_192f = /* @__PURE__ */ gen2(PARAMS2["192f"], SHA512_SIMPLE);
var slh_dsa_sha2_192s = /* @__PURE__ */ gen2(PARAMS2["192s"], SHA512_SIMPLE);
var slh_dsa_sha2_256f = /* @__PURE__ */ gen2(PARAMS2["256f"], SHA512_SIMPLE);
var slh_dsa_sha2_256s = /* @__PURE__ */ gen2(PARAMS2["256s"], SHA512_SIMPLE);

// node_modules/@noble/hashes/esm/sha256.js
var sha2563 = sha256;

// src/crypto.ts
var ED25519_PK = 32;
var ED25519_SIG = 64;
var MLDSA65_PK = 1952;
var MLDSA65_SIG = 3309;
var SLHDSA128S_PK = 32;
var SLHDSA128S_SIG = 7856;
function b64uDecode(s) {
  const b = s.replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(b, "base64"));
}
function b64uEncode(bytes) {
  return Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function verifyHybrid(pk, msg, sig) {
  if (sig.ed25519.length !== ED25519_SIG || sig.mldsa65.length !== MLDSA65_SIG) return "alg_downgrade";
  if (pk.ed25519.length !== ED25519_PK || pk.mldsa65.length !== MLDSA65_PK) return "sig_invalid";
  let ok;
  try {
    ok = ed25519.verify(sig.ed25519, msg, pk.ed25519);
  } catch {
    return "sig_invalid";
  }
  if (!ok) return "sig_invalid";
  try {
    if (!ml_dsa65.verify(pk.mldsa65, msg, sig.mldsa65)) return "sig_invalid";
  } catch {
    return "sig_invalid";
  }
  return null;
}
function ed25519Verify(pk, msg, sig) {
  if (pk.length !== ED25519_PK || sig.length !== ED25519_SIG) return false;
  try {
    return ed25519.verify(sig, msg, pk);
  } catch {
    return false;
  }
}
function slhVerify(pk, msg, sig) {
  if (pk.length !== SLHDSA128S_PK || sig.length !== SLHDSA128S_SIG) return false;
  const framed = new Uint8Array(2 + msg.length);
  framed[0] = 0;
  framed[1] = 0;
  framed.set(msg, 2);
  try {
    return slh_dsa_sha2_128s.verify(pk, framed, sig);
  } catch {
    return false;
  }
}
function hashLeaf(data) {
  const buf = new Uint8Array(1 + data.length);
  buf[0] = 0;
  buf.set(data, 1);
  return sha2563(buf);
}
function hashNode(l, r) {
  const buf = new Uint8Array(1 + 32 + 32);
  buf[0] = 1;
  buf.set(l, 1);
  buf.set(r, 33);
  return sha2563(buf);
}
function eq(a, b) {
  if (a.length !== b.length) return false;
  for (let i2 = 0; i2 < a.length; i2++) if (a[i2] !== b[i2]) return false;
  return true;
}
function verifyInclusion(leaf, index, treeSize, proof, root) {
  if (index >= treeSize) return false;
  let fn = index;
  let sn = treeSize - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = hashNode(p, r);
      if ((fn & 1) === 0) {
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = hashNode(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && eq(r, root);
}
function es256kVerify(pk, msg, sig) {
  if (pk.length !== 33 || pk[0] !== 2 && pk[0] !== 3 || sig.length !== 64) return false;
  try {
    const s = secp256k1.Signature.fromCompact(sig);
    if (s.hasHighS()) return false;
    return secp256k1.verify(sig, sha2563(msg), pk, { lowS: true, prehash: false, format: "compact" });
  } catch {
    return false;
  }
}
function secp256k1Affine(pk) {
  if (pk.length !== 33 || pk[0] !== 2 && pk[0] !== 3) return null;
  try {
    const u = secp256k1.ProjectivePoint.fromHex(pk).toRawBytes(false);
    return { x: u.slice(1, 33), y: u.slice(33, 65) };
  } catch {
    return null;
  }
}

// src/presentation.ts
var SIG_LABEL = "ainra";
var SIG_ALG = "ainra-hybrid-v1";
var PRESENTATION_HEADER = "x-ainra-passport";
var PRIME_PATH = "/.well-known/ainra-presentation";
var POP_HEADER = "x-ainra-pop";
var REF_RE = /^sha-256=:[A-Za-z0-9+/]{43}=:$/;
function isPresentationRef(v) {
  return REF_RE.test(v.trim());
}
function splitPresentation(bundle) {
  if (!bundle.instance || typeof bundle.instance !== "object") return { stable: { ...bundle }, pop: null };
  const { pop, ...instance } = bundle.instance;
  return { stable: { ...bundle, instance }, pop: pop ?? null };
}
function joinPresentation(stable, pop) {
  if (pop === null || pop === void 0 || !stable.instance) return { ...stable };
  return { ...stable, instance: { ...stable.instance, pop } };
}
function presentationRef(bundle) {
  const { stable } = splitPresentation(bundle);
  return `sha-256=:${b64std(sha2563(enc2.encode(canonicalize(stable))))}:`;
}
var MAX_AGE_SECS = 300;
var MAX_FUTURE_SECS = 30;
var enc2 = new TextEncoder();
function headerValue(h, name) {
  const lines = [];
  for (const k of Object.keys(h)) {
    if (k.toLowerCase() !== name) continue;
    const v = h[k];
    if (v === void 0) continue;
    for (const line of Array.isArray(v) ? v : [v]) lines.push(String(line).trim());
  }
  return lines.length ? lines.join(", ") : null;
}
function members(field) {
  const out = [];
  let start = 0, depth = 0, quoted = false, escaped = false;
  for (let i2 = 0; i2 < field.length; i2++) {
    const c = field[i2];
    if (quoted) {
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') quoted = false;
      continue;
    }
    if (c === '"') quoted = true;
    else if (c === "(") {
      if (depth) return null;
      depth = 1;
    } else if (c === ")") {
      if (!depth) return null;
      depth = 0;
    } else if (c === "," && !depth) {
      out.push(trimOws(field.slice(start, i2)));
      start = i2 + 1;
    }
  }
  if (quoted || depth) return null;
  out.push(trimOws(field.slice(start)));
  return out.every((m) => /^[a-z*][a-z0-9_.*-]*$/.test(memberKey(m))) ? out : null;
}
var trimOws = (s) => s.replace(/^[ \t]+|[ \t]+$/g, "");
var memberKey = (m) => m.slice(0, m.search(/[=;]/) < 0 ? m.length : m.search(/[=;]/));
function ownMember(ms) {
  const own = ms.filter((m) => memberKey(m) === SIG_LABEL);
  return own.length > 1 ? void 0 : own[0] ?? null;
}
function b64std(bytes) {
  const u = b64uEncode(bytes).replace(/-/g, "+").replace(/_/g, "/");
  return u + "=".repeat((4 - u.length % 4) % 4);
}
function b64stdDecode(s) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  const u = s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  try {
    const raw = b64uDecode(u);
    return b64uEncode(raw) === u ? raw : null;
  } catch {
    return null;
  }
}
function contentDigest(body) {
  return `sha-256=:${b64std(sha2563(body))}:`;
}
function coveredComponents(hasBody) {
  return hasBody ? ["@method", "@authority", "@path", "content-digest", PRESENTATION_HEADER] : ["@method", "@authority", "@path", PRESENTATION_HEADER];
}
function signatureBase(req, components, p) {
  const lines = [];
  for (const c of components) {
    let v;
    if (c === "@method") v = req.method.toUpperCase();
    else if (c === "@authority") v = req.authority.toLowerCase();
    else if (c === "@path") v = req.path;
    else if (c.startsWith("@")) return null;
    else v = headerValue(req.headers, c);
    if (v === null) return null;
    lines.push(`"${c}": ${v}`);
  }
  const list = components.map((c) => `"${c}"`).join(" ");
  lines.push(`"@signature-params": (${list});created=${p.created};keyid="${p.keyid}";alg="${SIG_ALG}";nonce="${p.nonce}"`);
  return lines.join("\n");
}
async function signPresentation(args) {
  const priorInput = headerValue(args.req.headers, "signature-input");
  const priorSig = headerValue(args.req.headers, "signature");
  if (priorInput === null !== (priorSig === null))
    throw new Error("cannot sign: the request carries half of another signature");
  if (priorInput !== null && priorSig !== null) {
    const im = members(priorInput), sm = members(priorSig);
    if (!im || !sm) throw new Error("cannot sign: the request's signature fields do not split into members");
    if (ownMember(im) !== null || ownMember(sm) !== null)
      throw new Error("cannot sign: the request already carries an ainra signature");
  }
  const out = {};
  const headers = { ...args.req.headers };
  if (args.req.body && args.req.body.length) {
    out["content-digest"] = contentDigest(args.req.body);
    headers["content-digest"] = out["content-digest"];
  }
  const components = coveredComponents(Boolean(args.req.body && args.req.body.length));
  const p = { created: args.created, keyid: args.keyid, nonce: args.nonce };
  const base = signatureBase({ ...args.req, headers }, components, p);
  if (base === null) throw new Error(`cannot sign: a covered component is missing (${components.join(", ")})`);
  const sig = await args.instanceSign(enc2.encode(base));
  if (sig.ed25519.length !== ED25519_SIG || sig.mldsa65.length !== MLDSA65_SIG)
    throw new Error("instanceSign returned a non-hybrid signature \u2014 both halves are mandatory (D-047)");
  const joined = new Uint8Array(ED25519_SIG + MLDSA65_SIG);
  joined.set(sig.ed25519, 0);
  joined.set(sig.mldsa65, ED25519_SIG);
  const input = `${SIG_LABEL}=(${components.map((c) => `"${c}"`).join(" ")});created=${p.created};keyid="${p.keyid}";alg="${SIG_ALG}";nonce="${p.nonce}"`;
  const signature = `${SIG_LABEL}=:${b64std(joined)}:`;
  out["signature-input"] = priorInput === null ? input : `${priorInput}, ${input}`;
  out["signature"] = priorSig === null ? signature : `${priorSig}, ${signature}`;
  return out;
}
var INPUT_RE = new RegExp(
  `^${SIG_LABEL}=\\(([^)]*)\\);created=(\\d{1,15});keyid="([^"]{1,64})";alg="([^"]{1,32})";nonce="([A-Za-z0-9._~-]{1,128})"$`
);
function verifyPresentation(args) {
  const inputField = headerValue(args.req.headers, "signature-input");
  const signatureField = headerValue(args.req.headers, "signature");
  if (inputField === null || signatureField === null) return { ok: false, reason: "presentation_unsigned" };
  const inputs = members(inputField), signatures = members(signatureField);
  if (!inputs || !signatures) return { ok: false, reason: "presentation_sig_invalid" };
  const input = ownMember(inputs), signature = ownMember(signatures);
  if (input === void 0 || signature === void 0) return { ok: false, reason: "presentation_sig_invalid" };
  if (input === null || signature === null) return { ok: false, reason: "presentation_unsigned" };
  const m = INPUT_RE.exec(input);
  if (!m) return { ok: false, reason: "presentation_sig_invalid" };
  const [, listRaw, createdRaw, keyid, alg, nonce] = m;
  if (alg !== SIG_ALG) return { ok: false, reason: "presentation_sig_invalid" };
  if (keyid !== args.instance.iid) return { ok: false, reason: "presentation_sig_invalid" };
  const components = listRaw.length ? listRaw.split(" ").map((s) => s.replace(/^"|"$/g, "")) : [];
  const hasBody = Boolean(args.req.body && args.req.body.length);
  const required = coveredComponents(hasBody);
  if (components.length !== required.length || components.some((c, i2) => c !== required[i2]))
    return { ok: false, reason: "presentation_sig_invalid" };
  const created = Number(createdRaw);
  const age = args.now - created;
  if (age > (args.maxAgeSecs ?? MAX_AGE_SECS) || -age > MAX_FUTURE_SECS) return { ok: false, reason: "presentation_stale" };
  if (hasBody) {
    const expected = contentDigest(args.req.body);
    if (headerValue(args.req.headers, "content-digest") !== expected)
      return { ok: false, reason: "presentation_sig_invalid" };
  }
  const sigField = new RegExp(`^${SIG_LABEL}=:([A-Za-z0-9+/]+={0,2}):$`).exec(signature);
  if (!sigField) return { ok: false, reason: "presentation_sig_invalid" };
  const raw = b64stdDecode(sigField[1]);
  if (!raw || raw.length !== ED25519_SIG + MLDSA65_SIG) return { ok: false, reason: "presentation_sig_invalid" };
  const base = signatureBase(args.req, components, { created, keyid, nonce });
  if (base === null) return { ok: false, reason: "presentation_sig_invalid" };
  const sig = { ed25519: raw.slice(0, ED25519_SIG), mldsa65: raw.slice(ED25519_SIG) };
  if (verifyHybrid(args.instance.ikey, enc2.encode(base), sig) !== null)
    return { ok: false, reason: "presentation_sig_invalid" };
  if (args.seenNonce && args.seenNonce(nonce)) return { ok: false, reason: "presentation_replayed" };
  return { ok: true, nonce, created };
}
function runPresentationVector(v) {
  const headers = {};
  for (const [k, val] of v.request.headers) (headers[k.toLowerCase()] ??= []).push(val);
  const r = verifyPresentation({
    req: {
      method: v.request.method,
      authority: v.request.authority,
      path: v.request.path,
      headers,
      body: v.request.body_b64u === null ? void 0 : b64uDecode(v.request.body_b64u)
    },
    instance: { iid: v.instance.iid, ikey: { ed25519: b64uDecode(v.instance.ikey.ed25519), mldsa65: b64uDecode(v.instance.ikey.mldsa65) } },
    now: v.now,
    maxAgeSecs: v.max_age_secs,
    seenNonce: (n) => v.seen_nonces.includes(n)
  });
  return r.ok ? { ok: true, nonce: r.nonce, created: r.created } : { ok: false, reason: r.reason };
}

// src/wimse.ts
var WIT_HEADER = "workload-identity-token";
var WIT_TYP = "wit+jwt";
var WIMSE_TAG = "wimse-workload-to-workload";
var WIT_MAX_SECS = 3600;
var WIMSE_SIG_MAX_SECS = 300;
var SKEW = 30;
var enc3 = new TextEncoder();
var strict = (s) => {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]+$/.test(s)) return null;
  try {
    const b = b64uDecode(s);
    return b64uEncode(b) === s ? b : null;
  } catch {
    return null;
  }
};
function trustDomainOf(name) {
  const m = /^(?:ainra|did:ainra):([a-z0-9-]+):([a-z0-9-]+):([a-z0-9-]+)(?:@.*)?$/.exec(name);
  return m ? `${m[3]}.${m[2]}.${m[1]}.ainra.org` : null;
}
function wimseIdentifier(name, iid) {
  const td2 = trustDomainOf(name);
  return td2 && /^[A-Za-z0-9._~-]{1,64}$/.test(iid) ? `wimse://${td2}/${iid}` : null;
}
function passportOf(bundle) {
  try {
    const claims = JSON.parse(Buffer.from(b64uDecode(bundle.claims)).toString("utf8"));
    const ed = strict(claims?.keys?.[0]?.ed25519);
    return typeof claims.sub === "string" && ed && ed.length === 32 ? { sub: claims.sub, ed25519: ed } : null;
  } catch {
    return null;
  }
}
async function mintWit(args) {
  const claims = JSON.parse(Buffer.from(b64uDecode(args.passportClaimsB64)).toString("utf8"));
  const sub = wimseIdentifier(claims.sub, args.iid);
  if (!sub) throw new Error("cannot mint a WIT: the passport name or the instance id does not form a WIMSE identifier");
  if (args.instanceEd25519Public.length !== 32) throw new Error("cannot mint a WIT: the instance key must be Ed25519");
  const life = Math.min(args.lifetimeSecs ?? WIT_MAX_SECS, WIT_MAX_SECS);
  const exp = Math.min(args.now + life, claims.exp);
  const header = { alg: "EdDSA", typ: WIT_TYP };
  const payload = {
    iss: claims.sub.replace(/@.*$/, "").replace(/^ainra:/, "did:ainra:"),
    sub,
    iat: args.now,
    exp,
    jti: args.iid,
    cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: b64uEncode(args.instanceEd25519Public), alg: "EdDSA" } }
  };
  const input = `${b64uEncode(enc3.encode(JSON.stringify(header)))}.${b64uEncode(enc3.encode(JSON.stringify(payload)))}`;
  const sig = await args.controlSignEd25519(enc3.encode(input));
  if (sig.length !== 64) throw new Error("controlSignEd25519 must return a 64-byte Ed25519 signature");
  return `${input}.${b64uEncode(sig)}`;
}
function pathAndQuery(target) {
  const i2 = target.indexOf("?");
  return i2 < 0 ? [target, "?"] : [target.slice(0, i2), target.slice(i2)];
}
var COVERED_IF_PRESENT = ["content-type", "content-digest", "authorization", "txn-token", WIT_HEADER];
function signatureBase2(req, components, params2) {
  const [p, q] = pathAndQuery(req.path);
  const lines = [];
  for (const c of components) {
    let v;
    if (c === "@method") v = req.method.toUpperCase();
    else if (c === "@path") v = p;
    else if (c === "@query") v = q;
    else if (c === "@authority") v = req.authority.toLowerCase();
    else if (c.startsWith("@")) return null;
    else v = headerValue(req.headers, c);
    if (v === null) return null;
    lines.push(`"${c}": ${v}`);
  }
  lines.push(`"@signature-params": ${params2}`);
  return lines.join("\n");
}
async function signWimseRequest(args) {
  if (!/^[A-Za-z0-9._~-]{8,128}$/.test(args.nonce)) throw new Error("cannot sign: nonce must be 8-128 of A-Z a-z 0-9 . _ ~ -");
  if (/["\\]/.test(args.audience) || !args.audience) throw new Error("cannot sign: audience must be a non-empty string without quotes");
  const out = { [WIT_HEADER]: args.wit };
  const headers = { ...args.req.headers, [WIT_HEADER]: args.wit };
  if (args.req.body && args.req.body.length) {
    out["content-digest"] = contentDigest(args.req.body);
    headers["content-digest"] = out["content-digest"];
  }
  const components = ["@method", "@path", "@query", ...COVERED_IF_PRESENT.filter((h) => headerValue(headers, h) !== null)];
  const expires = args.created + Math.min(args.expiresInSecs ?? 120, WIMSE_SIG_MAX_SECS);
  const params2 = `(${components.map((c) => `"${c}"`).join(" ")});created=${args.created};expires=${expires};nonce="${args.nonce}";tag="${WIMSE_TAG}";wimse-aud="${args.audience}"`;
  const base = signatureBase2({ ...args.req, headers }, components, params2);
  if (base === null) throw new Error("cannot sign: a covered component is missing");
  const sig = await args.instanceSignEd25519(enc3.encode(base));
  if (sig.length !== 64) throw new Error("instanceSignEd25519 must return a 64-byte Ed25519 signature");
  const priorInput = headerValue(args.req.headers, "signature-input");
  const priorSig = headerValue(args.req.headers, "signature");
  const label = "wimse";
  if (priorInput && (members(priorInput) ?? []).some((m) => memberKey(m) === label))
    throw new Error(`cannot sign: the request already carries a "${label}" signature`);
  const input = `${label}=${params2}`;
  const signature = `${label}=:${Buffer.from(sig).toString("base64")}:`;
  out["signature-input"] = priorInput ? `${priorInput}, ${input}` : input;
  out["signature"] = priorSig ? `${priorSig}, ${signature}` : signature;
  return out;
}
function params(rest) {
  const out = /* @__PURE__ */ new Map();
  const re = /^;([a-z*][a-z0-9_.*-]*)(?:=(?:(\d{1,15})|"((?:[^"\\]|\\.)*)"))?/;
  let s = rest;
  while (s.length) {
    const m = re.exec(s);
    if (!m || out.has(m[1])) return null;
    out.set(m[1], m[2] !== void 0 ? Number(m[2]) : m[3] !== void 0 ? m[3] : true);
    s = s.slice(m[0].length);
  }
  return out;
}
function verifyWimseRequest(args) {
  const v = args.verifier.verify(args.bundle, args.now);
  if (v.verdict !== "valid") return { ok: false, reason: v.reason };
  const passport = passportOf(args.bundle);
  if (!passport) return { ok: false, reason: "instance_sig_invalid" };
  const wit = headerValue(args.req.headers, WIT_HEADER);
  if (wit === null) return { ok: false, reason: "presentation_unsigned" };
  const parts = wit.split(".");
  if (parts.length !== 3) return { ok: false, reason: "instance_sig_invalid" };
  let header, claims;
  try {
    const h = strict(parts[0]), c = strict(parts[1]);
    if (!h || !c) return { ok: false, reason: "instance_sig_invalid" };
    header = JSON.parse(Buffer.from(h).toString("utf8"));
    claims = JSON.parse(Buffer.from(c).toString("utf8"));
  } catch {
    return { ok: false, reason: "instance_sig_invalid" };
  }
  const witSig = strict(parts[2]);
  if (header.typ !== WIT_TYP || header.alg !== "EdDSA" || !witSig || !ed25519Verify(passport.ed25519, enc3.encode(`${parts[0]}.${parts[1]}`), witSig))
    return { ok: false, reason: "instance_sig_invalid" };
  const td2 = trustDomainOf(passport.sub);
  const sub = typeof claims.sub === "string" ? claims.sub : "";
  if (!td2 || !sub.startsWith(`wimse://${td2}/`)) return { ok: false, reason: "instance_sig_invalid" };
  const exp = claims.exp, iat = claims.iat;
  if (typeof exp !== "number" || typeof iat !== "number" || exp - iat > WIT_MAX_SECS || iat > args.now + SKEW)
    return { ok: false, reason: "instance_sig_invalid" };
  if (args.now >= exp) return { ok: false, reason: "instance_expired" };
  const jwk = claims.cnf?.jwk;
  const ikey = strict(jwk?.x);
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || jwk.alg !== "EdDSA" || !ikey || ikey.length !== 32)
    return { ok: false, reason: "instance_sig_invalid" };
  const inputField = headerValue(args.req.headers, "signature-input");
  const sigField = headerValue(args.req.headers, "signature");
  if (inputField === null || sigField === null) return { ok: false, reason: "presentation_unsigned" };
  const inputs = members(inputField), sigs = members(sigField);
  if (!inputs || !sigs) return { ok: false, reason: "presentation_sig_invalid" };
  const tagged = inputs.filter((m2) => /;tag="wimse-workload-to-workload"(;|$)/.test(m2));
  if (tagged.length === 0) return { ok: false, reason: "presentation_unsigned" };
  if (tagged.length > 1) return { ok: false, reason: "presentation_sig_invalid" };
  const label = memberKey(tagged[0]);
  const m = /^[a-z*][a-z0-9_.*-]*=\(([^)]*)\)(.*)$/.exec(tagged[0]);
  const ownSig = sigs.filter((x2) => memberKey(x2) === label);
  if (!m || ownSig.length !== 1) return { ok: false, reason: "presentation_sig_invalid" };
  const components = m[1].length ? m[1].split(" ").map((c) => /^"[^"]+"$/.test(c) ? c.slice(1, -1) : "\0") : [];
  const p = params(m[2]);
  if (!p || components.includes("\0") || p.has("keyid") || p.has("alg")) return { ok: false, reason: "presentation_sig_invalid" };
  const need = ["@method", "@path", "@query", ...COVERED_IF_PRESENT.filter((h) => headerValue(args.req.headers, h) !== null)];
  if (need.some((c) => !components.includes(c))) return { ok: false, reason: "presentation_sig_invalid" };
  const created = p.get("created"), expires = p.get("expires"), nonce = p.get("nonce");
  if (typeof created !== "number" || typeof expires !== "number" || typeof nonce !== "string" || !nonce || p.get("wimse-aud") !== args.audience || expires - created > WIMSE_SIG_MAX_SECS || expires < created)
    return { ok: false, reason: "presentation_sig_invalid" };
  if (args.now > expires || created > args.now + SKEW) return { ok: false, reason: "presentation_stale" };
  if (args.req.body && args.req.body.length && headerValue(args.req.headers, "content-digest") !== contentDigest(args.req.body))
    return { ok: false, reason: "presentation_sig_invalid" };
  const sm = /^[a-z*][a-z0-9_.*-]*=:([A-Za-z0-9+/]+={0,2}):$/.exec(ownSig[0]);
  if (!sm) return { ok: false, reason: "presentation_sig_invalid" };
  const raw = new Uint8Array(Buffer.from(sm[1], "base64"));
  if (Buffer.from(raw).toString("base64") !== sm[1]) return { ok: false, reason: "presentation_sig_invalid" };
  const base = signatureBase2(args.req, components, `(${m[1]})${m[2]}`);
  if (base === null || !ed25519Verify(ikey, enc3.encode(base), raw)) return { ok: false, reason: "presentation_sig_invalid" };
  if (args.seenNonce && args.seenNonce(nonce)) return { ok: false, reason: "presentation_replayed" };
  return { ok: true, sub, nonce };
}

// src/engine.ts
var VALID = { verdict: "valid" };
var invalid = (reason) => ({ verdict: "invalid", reason });
var Reject = class extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
  reason;
};
function validateLabel(s) {
  if (s.length < 1 || s.length > 63) return false;
  for (let i2 = 0; i2 < s.length; i2++) {
    const c = s.charCodeAt(i2);
    const ok = c >= 97 && c <= 122 || c >= 48 && c <= 57 || c === 45;
    if (!ok) return false;
  }
  return s[0] !== "-" && s[s.length - 1] !== "-";
}
function validateVersion(s) {
  const parts = s.split(".");
  if (parts.length < 1 || parts.length > 3) return false;
  for (const p of parts) {
    if (p.length === 0) return false;
    if (!/^[0-9]+$/.test(p)) return false;
    if (p.length > 1 && p[0] === "0") return false;
  }
  return true;
}
function parseName(s) {
  const at = s.split("@");
  if (at.length !== 2) return false;
  if (!validateVersion(at[1])) return false;
  const p = at[0].split(":");
  if (p.length !== 4 || p[0] !== "ainra") return false;
  return validateLabel(p[1]) && validateLabel(p[2]) && validateLabel(p[3]);
}
function parseDidRegistrar(s) {
  const p = s.split(":");
  if (p.length !== 5 || p[0] !== "did" || p[1] !== "ainra") return null;
  if (!validateLabel(p[2]) || !validateLabel(p[3]) || !validateLabel(p[4])) return null;
  return p[2];
}
var FORBIDDEN_KEYS = /* @__PURE__ */ new Set([
  "email",
  "phone",
  "name",
  "full_name",
  "given_name",
  "family_name",
  "surname",
  "address",
  "street",
  "city",
  "postcode",
  "zip",
  "ssn",
  "national_id",
  "dob",
  "birthdate",
  "gender",
  "photo",
  "ip",
  "geolocation",
  "score",
  "trust_score",
  "reputation",
  "rating",
  "ranking",
  "karma",
  "credit_score",
  "price",
  "amount",
  "fee",
  "cost",
  "payment",
  "balance",
  "invoice_total",
  "currency",
  "wallet",
  "iban"
]);
var ALLOWED_TOP = /* @__PURE__ */ new Set([
  "vct",
  "iss",
  "sub",
  "nbf",
  "exp",
  "authority",
  "tier",
  "capabilities",
  "scope_ceiling",
  "keys",
  "cnf",
  "status",
  "log",
  "act_chain",
  "mandates",
  "mandates_root",
  "mandates_size",
  "transfer_history",
  "prev_leaf"
]);
var ALLOWED_AUTHORITY = /* @__PURE__ */ new Set(["class", "principal_proof"]);
var ALLOWED_KEY = /* @__PURE__ */ new Set(["ed25519", "mldsa65"]);
var ALLOWED_STATUS = /* @__PURE__ */ new Set(["status_list"]);
var ALLOWED_STATUSREF = /* @__PURE__ */ new Set(["idx", "uri"]);
var ALLOWED_LOG = /* @__PURE__ */ new Set(["leaf", "root", "checkpoint"]);
var ALLOWED_HOP = /* @__PURE__ */ new Set(["from", "to", "granted", "exp", "sig_ed25519", "sig_mldsa65", "sig_child_ed25519", "sig_child_mldsa65", "log_leaf"]);
var ALLOWED_MANDATE = /* @__PURE__ */ new Set(["id", "parent"]);
var VCT = "ainra/passport/v1";
function denyUnknown(o, allowed) {
  if (o === null || typeof o !== "object" || Array.isArray(o)) throw new Reject("schema_violation");
  for (const k of Object.keys(o)) if (!allowed.has(k)) throw new Reject("schema_violation");
}
function reqString(v) {
  if (typeof v !== "string") throw new Reject("schema_violation");
  return v;
}
function reqStringArray(v) {
  if (!Array.isArray(v) || v.some((x2) => typeof x2 !== "string")) throw new Reject("schema_violation");
  return v;
}
function scanForbidden(v) {
  if (Array.isArray(v)) {
    for (const it of v) scanForbidden(it);
  } else if (v !== null && typeof v === "object") {
    for (const [k, child] of Object.entries(v)) {
      if (FORBIDDEN_KEYS.has(k.toLowerCase())) throw new Reject("schema_violation");
      scanForbidden(child);
    }
  }
}
function parseChecked(claims) {
  let raw;
  try {
    raw = JSON.parse(Buffer.from(claims).toString("utf8"));
  } catch {
    throw new Reject("schema_violation");
  }
  scanForbidden(raw);
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw new Reject("schema_violation");
  const o = raw;
  for (const k of Object.keys(o)) if (!ALLOWED_TOP.has(k)) throw new Reject("schema_violation");
  if (o.vct !== VCT) throw new Reject("schema_violation");
  if (typeof o.sub !== "string" || !parseName(o.sub)) throw new Reject("name_malformed");
  if (typeof o.iss !== "string" || parseDidRegistrar(o.iss) === null) throw new Reject("name_malformed");
  denyUnknown(o.authority, ALLOWED_AUTHORITY);
  reqString(o.authority.class);
  reqString(o.authority.principal_proof);
  const keys = o.keys;
  if (!Array.isArray(keys) || keys.length === 0) throw new Reject("schema_violation");
  for (const k of keys) {
    denyUnknown(k, ALLOWED_KEY);
    const ke = k;
    if (typeof ke.ed25519 !== "string" || ke.ed25519.length === 0) throw new Reject("schema_violation");
    if (typeof ke.mldsa65 !== "string" || ke.mldsa65.length === 0) throw new Reject("schema_violation");
  }
  if (typeof o.nbf !== "number" || typeof o.exp !== "number" || o.exp <= o.nbf) throw new Reject("schema_violation");
  const capabilities = reqStringArray(o.capabilities);
  const scope_ceiling = reqStringArray(o.scope_ceiling);
  denyUnknown(o.status, ALLOWED_STATUS);
  const sl = o.status.status_list;
  denyUnknown(sl, ALLOWED_STATUSREF);
  const idx = sl.idx;
  if (typeof idx !== "number" || !Number.isInteger(idx) || idx < 0) throw new Reject("schema_violation");
  const statusUri = reqString(sl.uri);
  denyUnknown(o.log, ALLOWED_LOG);
  const logLeaf = reqString(o.log.leaf);
  reqString(o.log.root);
  reqString(o.log.checkpoint);
  if (o.act_chain !== void 0 && !Array.isArray(o.act_chain)) throw new Reject("schema_violation");
  const act_chain = o.act_chain ?? [];
  for (const hop of act_chain) {
    denyUnknown(hop, ALLOWED_HOP);
    if (!reqString(hop.from) || !parseName(hop.from)) throw new Reject("name_malformed");
    if (!reqString(hop.to) || !parseName(hop.to)) throw new Reject("name_malformed");
    reqStringArray(hop.granted);
    if (typeof hop.exp !== "number") throw new Reject("schema_violation");
    if (!hop.sig_ed25519 || !hop.sig_mldsa65 || !hop.sig_child_ed25519 || !hop.sig_child_mldsa65 || !hop.log_leaf)
      throw new Reject("schema_violation");
  }
  for (let i2 = 1; i2 < act_chain.length; i2++) {
    if (act_chain[i2].from !== act_chain[i2 - 1].to) throw new Reject("schema_violation");
  }
  if (act_chain.length > 0 && act_chain[act_chain.length - 1].to !== o.sub) throw new Reject("schema_violation");
  const mandates = o.mandates ?? [];
  if (o.mandates !== void 0 && !Array.isArray(o.mandates)) throw new Reject("schema_violation");
  for (const n of mandates) denyUnknown(n, ALLOWED_MANDATE);
  if (o.mandates_root !== void 0 || o.mandates_size !== void 0) throw new Reject("schema_violation");
  if (o.prev_leaf !== void 0 && o.prev_leaf !== null) {
    if (typeof o.prev_leaf !== "string") throw new Reject("schema_violation");
    const pl = strictB64u(o.prev_leaf);
    if (pl === null || pl.length !== 32 || b64uEncode(pl) !== o.prev_leaf) throw new Reject("schema_violation");
  }
  return {
    iss: o.iss,
    sub: o.sub,
    nbf: o.nbf,
    exp: o.exp,
    capabilities,
    scope_ceiling,
    statusIdx: idx,
    statusUri,
    logLeaf,
    act_chain,
    mandates,
    keys
  };
}
var FRESHNESS_MAX = Object.assign(/* @__PURE__ */ Object.create(null), { F1: 30, F2: 300, F3: 86400 });
var MAX_STATUS_BITS = 1 << 24;
function unpackStatus(compressed, bitLen2) {
  if (!Number.isInteger(bitLen2) || bitLen2 < 0 || bitLen2 > MAX_STATUS_BITS) throw new Reject("stale_status");
  const need = Math.ceil(bitLen2 / 8);
  let packed;
  try {
    packed = new Uint8Array(inflateSync(compressed, { maxOutputLength: need + 8 }));
  } catch {
    throw new Reject("stale_status");
  }
  if (packed.length < need) throw new Reject("stale_status");
  return packed;
}
function statusBit(packed, bitLen2, idx) {
  if (idx < 0 || idx >= bitLen2) return true;
  return (packed[idx >> 3] >> (idx & 7) & 1) === 1;
}
function subset(a, b) {
  return a.every((x2) => b.includes(x2));
}
function hopSigningBytes(h) {
  return new TextEncoder().encode(canonicalize({ from: h.from, to: h.to, granted: h.granted, exp: h.exp }));
}
function hopLeaf(h) {
  return hashLeaf(hopSigningBytes(h));
}
function checkMandatePath(path, revoked) {
  if (path.length === 0) return;
  if (path[0].parent !== null && path[0].parent !== void 0) throw new Reject("schema_violation");
  for (let i2 = 1; i2 < path.length; i2++) {
    if (path[i2].parent !== path[i2 - 1].id) throw new Reject("schema_violation");
  }
  if (path.some((n) => revoked.has(n.id))) throw new Reject("mandate_revoked");
}
var INSTANCE_CRED_DEFAULT_SECS = 60 * 60;
var POP_MAX_SKEW_SECS = 30;
var POP_MAX_FUTURE_SECS = 5;
var MAX_IID_LEN = 64;
var MAX_CAPABILITIES = 256;
function instanceSigningBytes(ic) {
  return new TextEncoder().encode(canonicalize({
    aud: ic.aud,
    capabilities: ic.capabilities,
    exp: ic.exp,
    iid: ic.iid,
    ikey: { ed25519: b64uEncode(ic.ikey.ed25519), mldsa65: b64uEncode(ic.ikey.mldsa65) },
    nbf: ic.nbf,
    passport_leaf: b64uEncode(ic.passportLeaf),
    sub: ic.sub
  }));
}
function instanceCredDigest(ic) {
  return sha2563(instanceSigningBytes(ic));
}
function popSigningBytes(pop, ic) {
  return new TextEncoder().encode(canonicalize({
    aud: pop.aud,
    cred: b64uEncode(instanceCredDigest(ic)),
    nonce: pop.nonce,
    ts: pop.ts
  }));
}
var SCOPE_CHECKPOINT = "checkpoint-daily";
var DELEGATE_CERT_MAX_SECS = 92 * 24 * 60 * 60;
var PASSPORT_VALIDITY_DEFAULT_SECS = 366 * 24 * 60 * 60;
var RENEWAL_LEAD_SECS = 30 * 24 * 60 * 60;
function renewalDue(exp, now) {
  return now >= exp - RENEWAL_LEAD_SECS;
}
function certFingerprintB64(c) {
  const bytes = new TextEncoder().encode(
    canonicalize({ delegate: b64uEncode(c.delegateEd25519), exp: c.exp, nbf: c.nbf, scopes: c.scopes })
  );
  return b64uEncode(sha2563(bytes));
}
function strictB64u(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  try {
    const b = b64uDecode(s);
    if (b64uEncode(b) !== s) return null;
    return b;
  } catch {
    return null;
  }
}
function dec(s, reason = "schema_violation") {
  const b = strictB64u(s);
  if (b === null) throw new Reject(reason);
  return b;
}
function decodeFingerprints(list) {
  const out = [];
  for (const s of list) {
    const b = strictB64u(s);
    if (b === null || b.length !== 32) return null;
    out.push(b64uEncode(b));
  }
  return out;
}
function verifyCheckpointSig(logRootKey, cp, sig, now) {
  const cpMsg = new TextEncoder().encode(canonicalize({ origin: cp.origin, root: cp.rootB64, size: cp.size }));
  if (sig.mode === "root") return slhVerify(logRootKey, cpMsg, sig.slh);
  const c = sig.cert;
  const certMsg = new TextEncoder().encode(
    canonicalize({ delegate: b64uEncode(c.delegateEd25519), exp: c.exp, nbf: c.nbf, scopes: c.scopes })
  );
  if (!slhVerify(logRootKey, certMsg, c.sigSlh)) return false;
  if (c.exp <= c.nbf || c.exp - c.nbf > DELEGATE_CERT_MAX_SECS) return false;
  if (now < c.nbf || now >= c.exp) return false;
  if (!c.scopes.includes(SCOPE_CHECKPOINT)) return false;
  return ed25519Verify(c.delegateEd25519, cpMsg, sig.sigEd25519);
}
var SCOPE_DELTA = "delta-countersign";
var SCOPE_FRESH_HEAD = "fresh-head";
function verifyDelegateCert(cert, rootKey, now, scope) {
  let certMsg;
  try {
    certMsg = new TextEncoder().encode(
      canonicalize({ delegate: b64uEncode(cert.delegateEd25519), exp: cert.exp, nbf: cert.nbf, scopes: cert.scopes })
    );
  } catch {
    return false;
  }
  if (!slhVerify(rootKey, certMsg, cert.sigSlh)) return false;
  if (cert.exp <= cert.nbf || cert.exp - cert.nbf > DELEGATE_CERT_MAX_SECS) return false;
  if (now < cert.nbf || now >= cert.exp) return false;
  if (!cert.scopes.includes(scope)) return false;
  return true;
}
function freshnessStale(freshness, now, issuedAt) {
  const max2 = FRESHNESS_MAX[freshness];
  if (max2 === void 0) return true;
  if (issuedAt > now) return true;
  return now - issuedAt > max2;
}
function deltaSigningBytes(d) {
  return new TextEncoder().encode(
    canonicalize({ from_seq: d.fromSeq, idx: d.idx, new_status: d.newStatus, seq: d.seq, ts: d.ts, uri: d.uri })
  );
}
function freshHeadSigningBytes(h) {
  return new TextEncoder().encode(
    canonicalize({ seq: h.seq, status_hash: b64uEncode(h.statusHash), ts: h.ts, uri: h.uri })
  );
}
function verifyDelta(d, registrarPub, rootKey, cert, now) {
  if (d.seq !== d.fromSeq + 1 || d.seq === 0) return "stale_status";
  for (let i2 = 1; i2 < d.idx.length; i2++) if (!(d.idx[i2 - 1] < d.idx[i2])) return "stale_status";
  let msg;
  try {
    msg = deltaSigningBytes(d);
  } catch {
    return "stale_status";
  }
  const h = verifyHybrid(registrarPub, msg, d.sigRegistrar);
  if (h) return h;
  if (!verifyDelegateCert(cert, rootKey, now, SCOPE_DELTA)) return "checkpoint_invalid";
  return ed25519Verify(cert.delegateEd25519, msg, d.countersigDelegate) ? null : "checkpoint_invalid";
}
function verifyFreshHead(head, rootKey, cert, now, freshness) {
  if (!verifyDelegateCert(cert, rootKey, now, SCOPE_FRESH_HEAD)) return "checkpoint_invalid";
  let msg;
  try {
    msg = freshHeadSigningBytes(head);
  } catch {
    return "checkpoint_invalid";
  }
  if (!ed25519Verify(cert.delegateEd25519, msg, head.sigDelegate)) return "checkpoint_invalid";
  return freshnessStale(freshness, now, head.ts) ? "stale_status" : null;
}
function headHash(uri, bitLen2, statusListB64) {
  return sha2563(new TextEncoder().encode(canonicalize({ bit_len: bitLen2, status_list: statusListB64, uri })));
}
function verify(pres, anchors) {
  try {
    verifyInner(pres, anchors);
    return VALID;
  } catch (e) {
    if (e instanceof Reject) return invalid(e.reason);
    throw e;
  }
}
function verifyInner(pres, anchors) {
  const p = parseChecked(pres.claims);
  const registrar = parseDidRegistrar(p.iss);
  if (registrar === null) throw new Reject("name_malformed");
  if (!Object.hasOwn(anchors, registrar)) throw new Reject("unknown_registrar");
  const reg = anchors[registrar];
  if (pres.now < p.nbf) throw new Reject("not_yet_valid");
  if (pres.now >= p.exp) throw new Reject("expired");
  const h = verifyHybrid(reg.issuerKey, pres.claims, pres.issuerSig);
  if (h) throw new Reject(h);
  if (!subset(p.capabilities, p.scope_ceiling)) throw new Reject("ceiling_exceeded");
  if (p.act_chain.length > 0) {
    if (pres.chainKeys.length !== p.act_chain.length + 1) throw new Reject("schema_violation");
    if (pres.hopProofs.length !== p.act_chain.length) throw new Reject("schema_violation");
    for (let i2 = 0; i2 < p.act_chain.length; i2++) {
      const hop = p.act_chain[i2];
      const msg = hopSigningBytes(hop);
      const parent = { ed25519: dec(hop.sig_ed25519, "alg_downgrade"), mldsa65: dec(hop.sig_mldsa65, "alg_downgrade") };
      const rp = verifyHybrid(pres.chainKeys[i2], msg, parent);
      if (rp) throw new Reject(rp);
      const child = { ed25519: dec(hop.sig_child_ed25519, "alg_downgrade"), mldsa65: dec(hop.sig_child_mldsa65, "alg_downgrade") };
      const rc = verifyHybrid(pres.chainKeys[i2 + 1], msg, child);
      if (rc) throw new Reject(rc);
    }
    let effCaps = p.act_chain[0].granted;
    let effExp = p.act_chain[0].exp;
    for (let i2 = 1; i2 < p.act_chain.length; i2++) {
      const hop = p.act_chain[i2];
      if (!subset(hop.granted, effCaps)) throw new Reject("chain_widening");
      if (hop.exp > effExp) throw new Reject("chain_expired");
      effCaps = hop.granted;
      effExp = hop.exp;
    }
    if (!subset(p.capabilities, effCaps)) throw new Reject("chain_widening");
    if (p.exp > effExp) throw new Reject("chain_expired");
  } else if (pres.chainKeys.length > 0 || pres.hopProofs.length > 0) {
    throw new Reject("schema_violation");
  }
  const maxAge = FRESHNESS_MAX[pres.freshness];
  if (maxAge === void 0) throw new Reject("stale_status");
  if (pres.statusIssuedAt > pres.now || pres.now - pres.statusIssuedAt > maxAge) throw new Reject("stale_status");
  const idx = p.statusIdx;
  const revoked = statusBit(pres.statusBits, pres.statusBitLen, idx);
  if (revoked) throw new Reject("revoked");
  if (pres.mandatePath.length > 0 || pres.mandateProofs.length > 0) throw new Reject("schema_violation");
  checkMandatePath(p.mandates, pres.mandateRevocations);
  if (!verifyCheckpointSig(reg.logRootKey, pres.checkpoint, pres.checkpointSig, pres.now))
    throw new Reject("checkpoint_invalid");
  if (pres.checkpointSig.mode === "delegate" && pres.revokedDelegates.has(certFingerprintB64(pres.checkpointSig.cert)))
    throw new Reject("checkpoint_invalid");
  const expectedLeaf = prelogLeaf(pres.claims);
  const claimedLeaf = dec(p.logLeaf, "not_logged");
  if (claimedLeaf.length !== 32 || !eqBytes(claimedLeaf, expectedLeaf)) throw new Reject("not_logged");
  if (!verifyInclusion(claimedLeaf, pres.leafIndex, pres.checkpoint.size, pres.inclusionProof, pres.checkpoint.root)) {
    throw new Reject("not_logged");
  }
  if (reg.distrustFromLeaf !== void 0 && pres.leafIndex >= reg.distrustFromLeaf)
    throw new Reject("registrar_distrusted");
  for (let i2 = 0; i2 < p.act_chain.length; i2++) {
    const hop = p.act_chain[i2];
    const anchored = dec(hop.log_leaf, "not_logged");
    const recomputed = hopLeaf(hop);
    if (anchored.length !== 32 || !eqBytes(anchored, recomputed)) throw new Reject("not_logged");
    const hp = pres.hopProofs[i2];
    if (!verifyInclusion(anchored, hp.leafIndex, pres.checkpoint.size, hp.proof, pres.checkpoint.root))
      throw new Reject("not_logged");
    if (reg.distrustFromLeaf !== void 0 && hp.leafIndex >= reg.distrustFromLeaf)
      throw new Reject("registrar_distrusted");
  }
  if (pres.instance) {
    verifyInstance(pres.instance.ic, pres.instance.pop, p, expectedLeaf, pres.now, pres.audience ?? "");
  }
}
function verifyInstance(ic, pop, p, passportLeaf, now, expectedAud) {
  if (ic.sub !== p.sub || !eqBytes(ic.passportLeaf, passportLeaf)) throw new Reject("instance_sig_invalid");
  if (ic.exp <= ic.nbf || ic.exp - ic.nbf > INSTANCE_CRED_DEFAULT_SECS) throw new Reject("instance_expired");
  if (now < ic.nbf || now >= ic.exp) throw new Reject("instance_expired");
  if (ic.capabilities.length > MAX_CAPABILITIES || p.capabilities.length > MAX_CAPABILITIES) throw new Reject("schema_violation");
  if (!ic.capabilities.every((c) => p.capabilities.includes(c))) throw new Reject("instance_scope_exceeds");
  const pkey = { ed25519: dec(p.keys[0].ed25519, "instance_sig_invalid"), mldsa65: dec(p.keys[0].mldsa65, "instance_sig_invalid") };
  if (verifyHybrid(pkey, instanceSigningBytes(ic), ic.sig)) throw new Reject("instance_sig_invalid");
  if (expectedAud === "" || ic.aud === "" || pop.aud === "") throw new Reject("instance_pop_invalid");
  if (ic.aud !== expectedAud || pop.aud !== expectedAud) throw new Reject("instance_pop_invalid");
  if (now - pop.ts > POP_MAX_SKEW_SECS || pop.ts - now > POP_MAX_FUTURE_SECS) throw new Reject("instance_pop_invalid");
  if (verifyHybrid(ic.ikey, popSigningBytes(pop, ic), pop.sig)) throw new Reject("instance_pop_invalid");
}
function prelogLeaf(claims) {
  let body;
  try {
    body = JSON.parse(Buffer.from(claims).toString("utf8"));
  } catch {
    throw new Reject("schema_violation");
  }
  delete body.log;
  return hashLeaf(new TextEncoder().encode(canonicalize(body)));
}
function eqBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i2 = 0; i2 < a.length; i2++) if (a[i2] !== b[i2]) return false;
  return true;
}
function decodeCheckpointSig(w) {
  if (w.mode === "root") return { mode: "root", slh: dec(w.slh ?? "") };
  const c = w.cert;
  return {
    mode: "delegate",
    cert: {
      delegateEd25519: dec(c.delegate_ed25519),
      scopes: c.scopes,
      nbf: c.nbf,
      exp: c.exp,
      sigSlh: dec(c.sig_slh)
    },
    sigEd25519: dec(w.sig_ed25519 ?? "")
  };
}
function decodeInstance(i2) {
  const int = (v) => {
    if (typeof v !== "number" || !Number.isInteger(v) || Object.is(v, -0) || v < 0) throw new Reject("schema_violation");
    return v;
  };
  const str = (v) => {
    if (typeof v !== "string") throw new Reject("schema_violation");
    return v;
  };
  if (!i2.pop || typeof i2.pop !== "object") throw new Reject("schema_violation");
  if (!Array.isArray(i2.capabilities) || i2.capabilities.some((c) => typeof c !== "string"))
    throw new Reject("schema_violation");
  if (typeof i2.iid !== "string" || i2.iid.length > MAX_IID_LEN) throw new Reject("schema_violation");
  if (i2.capabilities.length > MAX_CAPABILITIES) throw new Reject("schema_violation");
  return {
    ic: {
      sub: str(i2.sub),
      iid: str(i2.iid),
      ikey: { ed25519: dec(i2.ikey.ed25519), mldsa65: dec(i2.ikey.mldsa65) },
      nbf: int(i2.nbf),
      exp: int(i2.exp),
      capabilities: i2.capabilities,
      aud: str(i2.aud),
      passportLeaf: dec(i2.passport_leaf),
      sig: { ed25519: dec(i2.sig.ed25519), mldsa65: dec(i2.sig.mldsa65) }
    },
    pop: {
      aud: str(i2.pop.aud),
      nonce: str(i2.pop.nonce),
      ts: int(i2.pop.ts),
      sig: { ed25519: dec(i2.pop.sig.ed25519), mldsa65: dec(i2.pop.sig.mldsa65) }
    }
  };
}
function decodePresentation(pr, revoked, now, audience) {
  return {
    claims: dec(pr.claims),
    issuerSig: { ed25519: dec(pr.issuer_sig.ed25519), mldsa65: dec(pr.issuer_sig.mldsa65) },
    now,
    chainKeys: pr.chain_keys.map((k) => ({ ed25519: dec(k.ed25519), mldsa65: dec(k.mldsa65) })),
    hopProofs: pr.hop_proofs.map((hp) => ({ leafIndex: hp.leaf_index, proof: hp.proof.map((s) => dec(s)) })),
    statusBits: unpackStatus(dec(pr.status_list), pr.status_len),
    statusBitLen: pr.status_len,
    statusIssuedAt: pr.status_issued_at,
    // Read here only for the fixture path (a vector pins its class); the Verifier overwrites it with its own.
    freshness: pr.freshness,
    checkpoint: { origin: pr.checkpoint.origin, size: pr.checkpoint.size, root: dec(pr.checkpoint.root), rootB64: pr.checkpoint.root },
    checkpointSig: decodeCheckpointSig(pr.checkpoint_sig),
    leafIndex: pr.leaf_index,
    inclusionProof: pr.inclusion_proof.map((s) => dec(s)),
    mandatePath: [],
    mandateProofs: [],
    // Likewise: a vector's revocation set; the Verifier replaces it with the empty authenticated set.
    mandateRevocations: new Set(pr.mandate_revocations),
    revokedDelegates: revoked,
    instance: pr.instance ? decodeInstance(pr.instance) : void 0,
    audience
  };
}
function runVector(v) {
  try {
    const pr = v.presentation;
    const anchors = /* @__PURE__ */ Object.create(null);
    for (const [id2, r] of Object.entries(v.anchors)) {
      anchors[id2] = {
        issuerKey: { ed25519: dec(r.issuer_key.ed25519), mldsa65: dec(r.issuer_key.mldsa65) },
        logRootKey: dec(r.log_root_key),
        // D-044: wire is snake_case, the TS surface is camelCase. Forgetting this mapping is precisely how an
        // implementation silently returns VALID where the reference returns registrar_distrusted — which is what
        // `make diff` caught on the first run of these vectors.
        distrustFromLeaf: r.distrust_from_leaf ?? void 0
      };
    }
    const revoked = new Set(decodeFingerprints(pr.revoked_delegates ?? []) ?? (pr.revoked_delegates ?? []));
    return verify(decodePresentation(pr, revoked, pr.now, pr.audience ?? ""), anchors);
  } catch (e) {
    if (e instanceof Reject) return invalid(e.reason);
    throw e;
  }
}
function authenticateStatus(info, claimedUri, bundle) {
  const uri = bundle.status_uri;
  const sigEd = bundle.status_sig_ed25519;
  const sigMl = bundle.status_sig_mldsa65;
  if (typeof uri !== "string" || typeof sigEd !== "string" || typeof sigMl !== "string")
    throw new Reject("stale_status");
  if (uri !== info.statusUri || claimedUri !== info.statusUri) throw new Reject("stale_status");
  const ed = strictB64u(sigEd);
  const ml = strictB64u(sigMl);
  if (ed === null || ml === null) throw new Reject("stale_status");
  let signing;
  try {
    signing = new TextEncoder().encode(
      canonicalize({ bit_len: bundle.status_len, issued_at: bundle.status_issued_at, status_list: bundle.status_list, uri })
    );
  } catch {
    throw new Reject("stale_status");
  }
  if (verifyHybrid(info.statusKey, signing, { ed25519: ed, mldsa65: ml })) throw new Reject("stale_status");
}
function authenticateCurrency(info, bundle, now, seqSeen, revokedDelegates) {
  const fh = bundle.fresh_head;
  const wc = bundle.status_delegate_cert;
  if (!fh || !wc) throw new Reject("stale_status");
  const statusHash = strictB64u(fh.status_hash);
  const sigDelegate = strictB64u(fh.sig_delegate);
  const dEd = strictB64u(wc.delegate_ed25519);
  const dSlh = strictB64u(wc.sig_slh);
  if (statusHash === null || sigDelegate === null || dEd === null || dSlh === null) throw new Reject("stale_status");
  if (typeof fh.uri !== "string" || !Number.isInteger(fh.seq) || fh.seq < 0 || !Number.isInteger(fh.ts) || !Number.isInteger(wc.nbf) || !Number.isInteger(wc.exp) || !Array.isArray(wc.scopes) || wc.scopes.some((s) => typeof s !== "string")) {
    throw new Reject("stale_status");
  }
  const head = { uri: fh.uri, seq: fh.seq, ts: fh.ts, statusHash, sigDelegate };
  const cert = { delegateEd25519: dEd, scopes: wc.scopes, nbf: wc.nbf, exp: wc.exp, sigSlh: dSlh };
  if (verifyFreshHead(head, info.logRootKey, cert, now, "F1")) throw new Reject("stale_status");
  if (revokedDelegates.has(certFingerprintB64(cert))) throw new Reject("stale_status");
  if (head.uri !== info.statusUri) throw new Reject("stale_status");
  if (!eqBytes(headHash(head.uri, bundle.status_len, bundle.status_list), statusHash)) throw new Reject("stale_status");
  const seen = seqSeen.get(head.uri);
  if (seen !== void 0 && head.seq < seen) throw new Reject("stale_status");
  seqSeen.set(head.uri, seen === void 0 ? head.seq : Math.max(seen, head.seq));
}
var Verifier = class _Verifier {
  anchors;
  revokedDelegates;
  epoch;
  /** The verifier's freshness policy (default F2 = 5 min). The presenter's advertised class is ignored. */
  freshness;
  /** Currency mode: require + verify + head-hash-bind the fresh head and enforce a monotonic seq (D-021, M6). */
  currency;
  /** This verifier's own audience (ADR-019). An instance credential addressed elsewhere is refused. Empty string
   *  = this verifier accepts no instance credentials, which is the fail-closed default: a service that has not
   *  said who it is cannot be the intended recipient of anything. */
  audience;
  /** Per-uri highest fresh-head `seq` this verifier has observed (currency mode). A lower seq is a replay. */
  seqSeen = /* @__PURE__ */ new Map();
  constructor(acc, freshness, currency, audience) {
    this.anchors = acc.anchors;
    this.revokedDelegates = acc.revokedDelegates;
    this.epoch = acc.epoch;
    this.freshness = freshness;
    this.currency = currency;
    this.audience = audience;
  }
  /** Verify the dual-root-signed directory and build a Verifier; `null` if the directory is not authentic.
   *  `freshness` sets the verifier's own status-freshness policy (default `"F2"` = 5 min). `currency` (default
   *  `false`) enables the fresh-head + monotonic-seq replay defence (see the class docs). */
  static fromDirectory(d, rootEd25519, rootSlh, freshness = "F2", currency = false, audience = "") {
    const acc = verifyDirectory(d, rootEd25519, rootSlh);
    return acc === null ? null : new _Verifier(acc, freshness, currency, audience);
  }
  /** Convenience: build from a directory + the ceremony's base64url root keys (as published in `roots.json`). */
  static fromDirectoryB64(d, rootEd25519B64, rootSlhB64, freshness = "F2", currency = false, audience = "") {
    let ed, slh;
    try {
      ed = dec(rootEd25519B64);
      slh = dec(rootSlhB64);
    } catch {
      return null;
    }
    return _Verifier.fromDirectory(d, ed, slh, freshness, currency, audience);
  }
  /** Verify one presentation at the verifier's own `now` (unix seconds). The verifier supplies the clock, the
   * directory's revoked-delegate set, its own freshness policy, and an EMPTY mandate-revocation set; and it
   * authenticates the presented status list against the registrar's directory status key before trusting any bit.
   * The presenter cannot dictate any of these. Never throws. */
  verify(bundle, now) {
    try {
      const p = parseChecked(dec(bundle.claims));
      const registrar = parseDidRegistrar(p.iss);
      if (registrar === null) throw new Reject("name_malformed");
      if (!Object.hasOwn(this.anchors, registrar)) throw new Reject("unknown_registrar");
      const info = this.anchors[registrar];
      if (!info.statusKey) throw new Reject("stale_status");
      authenticateStatus(info, p.statusUri, bundle);
      if (this.currency) authenticateCurrency(info, bundle, now, this.seqSeen, this.revokedDelegates);
      const pres = decodePresentation(bundle, this.revokedDelegates, now, this.audience);
      pres.mandateRevocations = /* @__PURE__ */ new Set();
      pres.freshness = this.freshness;
      return verify(pres, this.anchors);
    } catch (e) {
      if (e instanceof Reject) return invalid(e.reason);
      return invalid("schema_violation");
    }
  }
  /** AINRA Link (D-078): who stands behind `presentedKey` — a 32-byte Ed25519 key, or a 33-byte compressed secp256k1
   *  point (ES256K, D-082) — a key this gate has ALREADY verified the
   *  request's signature with. Uses the directory's anchors and revoked delegates, this verifier's freshness class,
   *  and authenticates the status publication before reading a bit. `capability` is what the request exercises.
   *  A key with no link is the caller's outcome ("not linked") — this checks the link it is given. Never throws. */
  /** Check a registrar's receipt for a gate's logged decision head (D-081) against this verifier's accredited
   *  registrars: the statement names and was signed by `gateKey`, and it is logged under a checkpoint the
   *  registrar's log key signed. Never throws. */
  verifyHeadReceipt(receipt, gateKey, now) {
    try {
      return { verdict: "valid", statement: verifyHeadReceiptInner(receipt, this.anchors, this.revokedDelegates, gateKey, now) };
    } catch (e) {
      if (e instanceof Reject) return { verdict: "invalid", reason: e.reason };
      return { verdict: "invalid", reason: "schema_violation" };
    }
  }
  verifyLink(link, presentedKey, now, capability) {
    try {
      return { verdict: "valid", ...verifyLinkInner(link, this.anchors, this.revokedDelegates, presentedKey, now, this.freshness, capability) };
    } catch (e) {
      if (e instanceof Reject) return { verdict: "invalid", reason: e.reason };
      return { verdict: "invalid", reason: "schema_violation" };
    }
  }
};
function expectedVerdict(v) {
  return v.expect.verdict === "valid" ? VALID : invalid(v.expect.reason);
}
function decodeDeltaCert(c) {
  return {
    delegateEd25519: dec(c.delegate_ed25519),
    scopes: c.scopes,
    nbf: c.nbf,
    exp: c.exp,
    sigSlh: dec(c.sig_slh)
  };
}
function runDeltaVector(v) {
  const rootKey = dec(v.root_pub_slh);
  const cert = decodeDeltaCert(v.cert);
  let r;
  if (v.kind === "delta") {
    const delta = {
      uri: v.uri,
      fromSeq: v.from_seq,
      seq: v.seq,
      ts: v.ts,
      idx: v.idx,
      newStatus: v.new_status,
      sigRegistrar: { ed25519: dec(v.sig_registrar.ed25519), mldsa65: dec(v.sig_registrar.mldsa65) },
      countersigDelegate: dec(v.countersig_delegate)
    };
    const registrarPub = {
      ed25519: dec(v.registrar_pub.ed25519),
      mldsa65: dec(v.registrar_pub.mldsa65)
    };
    r = verifyDelta(delta, registrarPub, rootKey, cert, v.now);
  } else {
    const head = {
      uri: v.uri,
      seq: v.seq,
      ts: v.ts,
      statusHash: dec(v.status_hash),
      sigDelegate: dec(v.sig_delegate)
    };
    r = verifyFreshHead(head, rootKey, cert, v.now, v.freshness ?? "F1");
  }
  return r === null ? { accept: true } : { accept: false, reason: r };
}
function verifyDirectory(d, rootEd25519, rootSlh) {
  const revoked = d.revoked_delegates ?? [];
  let msg;
  try {
    msg = new TextEncoder().encode(
      canonicalize({ entries: d.entries, epoch: d.epoch, issued_at: d.issued_at, revoked_delegates: revoked })
    );
  } catch {
    return null;
  }
  let edSig;
  try {
    edSig = dec(d.sig_root_ed25519);
  } catch {
    return null;
  }
  if (edSig.length !== 64 || !ed25519Verify(rootEd25519, msg, edSig)) return null;
  let slhSig;
  try {
    slhSig = dec(d.sig_root_slh);
  } catch {
    return null;
  }
  if (!slhVerify(rootSlh, msg, slhSig)) return null;
  for (const e of d.entries) if (e.registrar.length === 0 || !/^[\x00-\x7f]*$/.test(e.registrar)) return null;
  for (let i2 = 1; i2 < d.entries.length; i2++) {
    if (d.entries[i2 - 1].registrar >= d.entries[i2].registrar) return null;
  }
  const anchors = /* @__PURE__ */ Object.create(null);
  for (const e of d.entries) {
    const ed = strictB64u(e.issuer_ed25519);
    const ml = strictB64u(e.issuer_mldsa65);
    const lr = strictB64u(e.log_root_slh);
    if (ed === null || ml === null || lr === null) return null;
    if (ed.length !== 32) return null;
    const info = {
      issuerKey: { ed25519: ed, mldsa65: ml },
      logRootKey: lr,
      distrustFromLeaf: typeof e.distrust_from_leaf === "number" ? e.distrust_from_leaf : void 0
    };
    const sEd = strictB64u(e.status_ed25519 ?? "");
    const sMl = strictB64u(e.status_mldsa65 ?? "");
    if (sEd !== null && sEd.length === 32 && sMl !== null && sMl.length > 0 && e.status_uri.length > 0) {
      info.statusKey = { ed25519: sEd, mldsa65: sMl };
      info.statusUri = e.status_uri;
    }
    anchors[e.registrar] = info;
  }
  const revNorm = decodeFingerprints(revoked);
  if (revNorm === null) return null;
  return { anchors, revokedDelegates: new Set(revNorm), epoch: d.epoch };
}
function verifyDirectoryAtLeast(d, rootEd25519, rootSlh, minEpoch) {
  const acc = verifyDirectory(d, rootEd25519, rootSlh);
  if (acc === null) return { ok: false, refusal: "unauthentic" };
  if (acc.epoch < minEpoch) return { ok: false, refusal: "rollback", epoch: acc.epoch, floor: minEpoch };
  return { ok: true, accredited: acc };
}
function verifyLogCheckpoint(d, rootEd25519, rootSlh, checkpoint, checkpointSig, now) {
  const acc = verifyDirectory(d, rootEd25519, rootSlh);
  if (acc === null || typeof checkpoint?.origin !== "string" || !checkpoint.origin.startsWith("ainra-log/")) return null;
  const registrar = checkpoint.origin.slice("ainra-log/".length);
  if (!Object.hasOwn(acc.anchors, registrar) || !isU64(checkpoint.size) || !isU64(now)) return null;
  try {
    if (dec(checkpoint.root).length !== 32) return null;
    const sig = decodeCheckpointSig(checkpointSig);
    if (!verifyCheckpointSig(acc.anchors[registrar].logRootKey, { origin: checkpoint.origin, rootB64: checkpoint.root, size: checkpoint.size }, sig, now))
      return null;
    if (sig.mode === "delegate" && acc.revokedDelegates.has(certFingerprintB64(sig.cert))) return null;
  } catch {
    return null;
  }
  return registrar;
}
function createDirectoryHolder(o) {
  let floor = o.minEpoch ?? 0;
  return {
    /** The epoch below which a directory is refused. */
    floor() {
      return floor;
    },
    accept(d) {
      const r = verifyDirectoryAtLeast(d, o.rootEd25519, o.rootSlh, floor);
      if (r.ok) floor = r.accredited.epoch;
      return r;
    },
    /** A {@link Verifier} built from `d`, only if this holder accepts it; otherwise the refusal. */
    verifier(d, freshness = "F2", currency = false, audience = "") {
      const r = this.accept(d);
      if (!r.ok) return r;
      return Verifier.fromDirectory(d, o.rootEd25519, o.rootSlh, freshness, currency, audience);
    }
  };
}
function runDirectoryEpochVector(v) {
  let ed = null, slh = null;
  try {
    ed = dec(v.root_ed25519);
    slh = dec(v.root_slh);
  } catch {
    ed = slh = null;
  }
  const holder = ed && slh && ed.length === 32 ? createDirectoryHolder({ rootEd25519: ed, rootSlh: slh, minEpoch: v.min_epoch ?? 0 }) : null;
  return (v.directories ?? []).map((d) => {
    if (!holder) return { accept: false, refusal: "unauthentic" };
    const r = holder.accept(d);
    return r.ok ? { accept: true, epoch: r.accredited.epoch, registrars: Object.keys(r.accredited.anchors).length } : { accept: false, refusal: r.refusal };
  });
}
function runDirectoryVector(v) {
  const acc = verifyDirectory(v.directory, dec(v.root_ed25519), dec(v.root_slh));
  if (acc === null) return { accept: false };
  return { accept: true, registrars: Object.keys(acc.anchors).length };
}
function numberFromName(sub) {
  const m = /^ainra:([a-z0-9-]+):([a-z0-9-]+):([a-z0-9-]+)@/.exec(sub);
  return m ? `did:ainra:${m[1]}:${m[2]}:${m[3]}` : null;
}
function verdictEvent(pres, verdict, now) {
  let name = null, number = null, tier = null, age = null;
  try {
    if (typeof pres.claims === "string") {
      const bytes = strictB64u(pres.claims);
      if (bytes) {
        const c = JSON.parse(new TextDecoder().decode(bytes));
        if (typeof c.sub === "string") {
          name = c.sub;
          number = numberFromName(c.sub);
        }
        if (typeof c.tier === "string") tier = c.tier;
      }
    }
    if (typeof pres.status_issued_at === "number") age = Math.max(0, Math.trunc(now - pres.status_issued_at));
  } catch {
  }
  const inst = pres.instance;
  const instance_iid = typeof inst?.iid === "string" && inst.iid.length <= MAX_IID_LEN ? inst.iid : null;
  const instance_exp = typeof inst?.exp === "number" ? inst.exp : null;
  return { status: verdict.verdict, reason: verdict.verdict === "valid" ? null : verdict.reason, name, number, tier, freshness_age_s: age, instance_iid, instance_exp };
}
function serializeVerdictEvent(e) {
  return JSON.stringify({ status: e.status, reason: e.reason, name: e.name, number: e.number, tier: e.tier, freshness_age_s: e.freshness_age_s, instance_iid: e.instance_iid, instance_exp: e.instance_exp });
}
async function mintInstanceCredential(args) {
  const claims = strictB64u(args.passportClaimsB64);
  if (!claims) throw new Error("passportClaimsB64 is not canonical base64url");
  const parsed = JSON.parse(new TextDecoder().decode(claims));
  const life = Math.min(args.lifetimeSecs ?? INSTANCE_CRED_DEFAULT_SECS, INSTANCE_CRED_DEFAULT_SECS);
  const extra = args.capabilities.filter((c) => !parsed.capabilities.includes(c));
  if (extra.length) throw new Error(`instance capabilities must narrow: ${extra.join(", ")} not held by the passport`);
  const ic = {
    sub: parsed.sub,
    iid: args.iid,
    ikey: args.instancePublic,
    nbf: args.now,
    exp: args.now + life,
    capabilities: args.capabilities,
    aud: args.audience,
    passportLeaf: prelogLeaf(claims),
    sig: { ed25519: new Uint8Array(), mldsa65: new Uint8Array() }
  };
  ic.sig = await args.controlSign(instanceSigningBytes(ic));
  return ic;
}
async function proveInstancePossession(args) {
  if (!args.credential || typeof args.credential !== "object") throw new Reject("schema_violation");
  if (!args.audience) throw new Reject("schema_violation");
  if (args.credential.aud !== args.audience) throw new Reject("schema_violation");
  const pop = {
    aud: args.audience,
    nonce: args.nonce,
    ts: args.now,
    sig: { ed25519: new Uint8Array(), mldsa65: new Uint8Array() }
  };
  pop.sig = await args.instanceSign(popSigningBytes(pop, args.credential));
  return pop;
}
var LINK_V = "ainra-link-1";
var LINK_POP_PURPOSE = "ainra-link-pop-1";
var ALLOWED_LINK = /* @__PURE__ */ new Set(["v", "registrar", "passport", "subject", "scope", "nbf", "exp", "status", "passport_status", "pop", "log"]);
var ALLOWED_LINK_SUBJECT = /* @__PURE__ */ new Set(["kind", "alg", "thumbprint"]);
var ALLOWED_LINK_LOG = /* @__PURE__ */ new Set(["leaf"]);
function isU64(v) {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}
function parseLinkChecked(raw) {
  let o;
  try {
    o = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch {
    throw new Reject("schema_violation");
  }
  if (typeof o !== "object" || o === null || Array.isArray(o)) throw new Reject("schema_violation");
  denyUnknown(o, ALLOWED_LINK);
  for (const k of ALLOWED_LINK) if (!Object.hasOwn(o, k)) throw new Reject("schema_violation");
  const subject = o.subject;
  const status = o.status;
  const pstatus = o.passport_status;
  const log = o.log;
  for (const [obj, allowed] of [[subject, ALLOWED_LINK_SUBJECT], [status, ALLOWED_STATUSREF], [pstatus, ALLOWED_STATUSREF], [log, ALLOWED_LINK_LOG]]) {
    if (typeof obj !== "object" || obj === null || Array.isArray(obj)) throw new Reject("schema_violation");
    denyUnknown(obj, allowed);
    for (const k of allowed) if (!Object.hasOwn(obj, k)) throw new Reject("schema_violation");
  }
  const v = reqString(o.v);
  const registrar = reqString(o.registrar);
  const passport = reqString(o.passport);
  const kind = reqString(subject.kind);
  const alg = reqString(subject.alg);
  const thumbprint = reqString(subject.thumbprint);
  const scope = reqStringArray(o.scope);
  const popB64 = reqString(o.pop);
  const leafB64 = reqString(log.leaf);
  const statusUri = reqString(status.uri);
  const passportUri = reqString(pstatus.uri);
  if (!isU64(o.nbf) || !isU64(o.exp) || !isU64(status.idx) || !isU64(pstatus.idx)) throw new Reject("schema_violation");
  let again;
  try {
    again = canonicalize(o);
  } catch {
    throw new Reject("schema_violation");
  }
  if (!eqBytes(new TextEncoder().encode(again), raw)) throw new Reject("schema_violation");
  if (v !== LINK_V || kind !== "jwk" || alg !== "Ed25519" && alg !== "ES256K") throw new Reject("schema_violation");
  const tp = strictB64u(thumbprint);
  const pop = strictB64u(popB64);
  const leaf = strictB64u(leafB64);
  if (tp === null || tp.length !== 32 || pop === null || pop.length !== 64 || leaf === null || leaf.length !== 32)
    throw new Reject("schema_violation");
  if (scope.length > MAX_CAPABILITIES || scope.some((s) => s.length === 0 || new TextEncoder().encode(s).length > 128))
    throw new Reject("schema_violation");
  if (statusUri !== passportUri || status.idx === pstatus.idx) throw new Reject("schema_violation");
  if (o.nbf >= o.exp) throw new Reject("schema_violation");
  if (!parseName(passport)) throw new Reject("name_malformed");
  if (passport.split(":")[1] !== registrar) throw new Reject("schema_violation");
  return {
    registrar,
    passport,
    alg,
    thumbprint,
    scope,
    nbf: o.nbf,
    exp: o.exp,
    statusUri,
    statusIdx: status.idx,
    passportIdx: pstatus.idx,
    pop,
    leaf
  };
}
function jwkThumbprintEs256k(pk) {
  const p = secp256k1Affine(pk);
  if (!p) return null;
  return b64uEncode(sha2563(new TextEncoder().encode(canonicalize({ crv: "secp256k1", kty: "EC", x: b64uEncode(p.x), y: b64uEncode(p.y) }))));
}
function presentedKeyThumbprint(pk) {
  return jwkThumbprintOf(pk);
}
function jwkThumbprintOf(pk) {
  return pk.length === 32 ? jwkThumbprintEd25519(pk) : pk.length === 33 ? jwkThumbprintEs256k(pk) : null;
}
function jwkThumbprintEd25519(pk) {
  return b64uEncode(sha2563(new TextEncoder().encode(canonicalize({ crv: "Ed25519", kty: "OKP", x: b64uEncode(pk) }))));
}
function linkPopSigningBytes(registrar, passport, thumbprint, nbf) {
  return new TextEncoder().encode(canonicalize({ purpose: LINK_POP_PURPOSE, registrar, passport, thumbprint, nbf }));
}
function verifyLinkInner(w, anchors, revokedDelegates, presentedKey, now, freshness, capability) {
  const raw = dec(w.claims);
  const c = parseLinkChecked(raw);
  if (!Object.hasOwn(anchors, c.registrar)) throw new Reject("unknown_registrar");
  const reg = anchors[c.registrar];
  if (!reg.statusKey) throw new Reject("stale_status");
  authenticateStatus(reg, c.statusUri, w);
  const packed = (() => {
    const z = strictB64u(w.status_list);
    if (z === null) throw new Reject("stale_status");
    return unpackStatus(z, w.status_len);
  })();
  const sig = { ed25519: dec(w.registrar_sig.ed25519), mldsa65: dec(w.registrar_sig.mldsa65) };
  const cpRoot = dec(w.checkpoint.root);
  if (cpRoot.length !== 32) throw new Reject("schema_violation");
  const cpSig = decodeCheckpointSig(w.checkpoint_sig);
  const proof = w.inclusion_proof.map((h) => {
    const b = dec(h);
    if (b.length !== 32) throw new Reject("schema_violation");
    return b;
  });
  if (!isU64(w.leaf_index) || !isU64(w.status_issued_at) || !isU64(w.checkpoint.size)) throw new Reject("schema_violation");
  if (now < c.nbf) throw new Reject("not_yet_valid");
  if (now >= c.exp) throw new Reject("expired");
  const r = verifyHybrid(reg.issuerKey, raw, sig);
  if (r) throw new Reject(r);
  const presentedAlg = presentedKey.length === 32 ? "Ed25519" : presentedKey.length === 33 ? "ES256K" : null;
  if (presentedAlg !== c.alg || jwkThumbprintOf(presentedKey) !== c.thumbprint) throw new Reject("sig_invalid");
  const consent = linkPopSigningBytes(c.registrar, c.passport, c.thumbprint, c.nbf);
  if (!(presentedAlg === "Ed25519" ? ed25519Verify(presentedKey, consent, c.pop) : es256kVerify(presentedKey, consent, c.pop)))
    throw new Reject("sig_invalid");
  if (capability !== void 0 && c.scope.length > 0 && !c.scope.includes(capability)) throw new Reject("ceiling_exceeded");
  if (freshnessStale(freshness, now, w.status_issued_at)) throw new Reject("stale_status");
  if (statusBit(packed, w.status_len, c.statusIdx)) throw new Reject("revoked");
  if (statusBit(packed, w.status_len, c.passportIdx)) throw new Reject("revoked");
  if (!verifyCheckpointSig(reg.logRootKey, { origin: w.checkpoint.origin, rootB64: w.checkpoint.root, size: w.checkpoint.size }, cpSig, now))
    throw new Reject("checkpoint_invalid");
  if (cpSig.mode === "delegate" && revokedDelegates.has(certFingerprintB64(cpSig.cert))) throw new Reject("checkpoint_invalid");
  if (!eqBytes(c.leaf, prelogLeaf(raw))) throw new Reject("not_logged");
  if (!verifyInclusion(c.leaf, w.leaf_index, w.checkpoint.size, proof, cpRoot)) throw new Reject("not_logged");
  if (reg.distrustFromLeaf !== void 0 && w.leaf_index >= reg.distrustFromLeaf) throw new Reject("registrar_distrusted");
  return { registrar: c.registrar, operator: c.passport.split(":")[2], passport: c.passport, scope: c.scope };
}
function linkFromIndex(index, publication, thumbprint) {
  const e = index.links.find((l) => l.thumbprint === thumbprint);
  if (!e) return null;
  return {
    claims: e.claims,
    registrar_sig: e.registrar_sig,
    leaf_index: e.leaf_index,
    inclusion_proof: e.inclusion_proof,
    checkpoint: index.checkpoint,
    checkpoint_sig: index.checkpoint_sig,
    status_list: publication.status_list_b64,
    status_len: publication.bit_len,
    status_issued_at: publication.issued_at,
    status_uri: publication.uri,
    status_sig_ed25519: publication.sig_ed25519,
    status_sig_mldsa65: publication.sig_mldsa65
  };
}
function runGateVector(v) {
  const gate = Verifier.fromDirectoryB64(v.directory, v.roots.root_ed25519, v.roots.root_slh, v.freshness, false, v.audience);
  if (!gate) return { verdict: "no_gate" };
  const r = gate.verify(v.bundle, v.now);
  return r.verdict === "valid" ? { verdict: "valid" } : { verdict: "invalid", reason: r.reason };
}
function runCurrencyVector(v) {
  const gate = Verifier.fromDirectoryB64(v.directory, v.roots.root_ed25519, v.roots.root_slh, v.freshness, true, v.audience);
  if (!gate) return { verdict: "no_gate" };
  return v.steps.map((s) => {
    const r = gate.verify(s.bundle, s.now);
    return r.verdict === "valid" ? { verdict: "valid" } : { verdict: "invalid", reason: r.reason };
  });
}
function runLinkVector(v) {
  const gate = Verifier.fromDirectoryB64(v.directory, v.roots.root_ed25519, v.roots.root_slh, v.freshness);
  if (!gate) return { verdict: "no_gate" };
  const key = strictB64u(v.presented_key);
  if (key === null || key.length !== 32 && key.length !== 33) return { verdict: "invalid", reason: "schema_violation" };
  return gate.verifyLink(v.link, key, v.now, v.capability ?? void 0);
}
var DECISION_V = "ainra-decision-1";
var DECISION_FIELDS = /* @__PURE__ */ new Set(["v", "gate", "seq", "at", "kind", "subject", "passport", "operator", "verdict", "reason", "request", "status", "checkpoint", "policy", "prev", "sig"]);
var DECISION_OPTIONAL = /* @__PURE__ */ new Set(["passport", "operator", "reason", "status", "checkpoint"]);
var FROZEN_REASONS = /* @__PURE__ */ new Set([
  "registrar_distrusted",
  "sig_invalid",
  "alg_downgrade",
  "expired",
  "not_yet_valid",
  "revoked",
  "mandate_revoked",
  "chain_widening",
  "chain_expired",
  "not_logged",
  "checkpoint_invalid",
  "stale_status",
  "name_malformed",
  "ceiling_exceeded",
  "unknown_registrar",
  "schema_violation",
  "instance_expired",
  "instance_scope_exceeds",
  "instance_sig_invalid",
  "instance_pop_invalid"
]);
var PRESENTATION_REASONS = /* @__PURE__ */ new Set(["presentation_unsigned", "presentation_sig_invalid", "presentation_stale", "presentation_replayed"]);
function b64Len(s, n) {
  if (typeof s !== "string") return false;
  const b = strictB64u(s);
  return b !== null && b.length === n;
}
function exactObject(o, fields) {
  if (o === null || typeof o !== "object" || Array.isArray(o)) return false;
  const keys = Object.keys(o);
  return keys.length === fields.length && fields.every((f) => Object.hasOwn(o, f));
}
function parseDecision(line) {
  let o;
  try {
    o = JSON.parse(line);
  } catch {
    return null;
  }
  if (o === null || typeof o !== "object" || Array.isArray(o)) return null;
  for (const k of Object.keys(o)) if (!DECISION_FIELDS.has(k)) return null;
  for (const k of DECISION_FIELDS) {
    if (!Object.hasOwn(o, k)) {
      if (!DECISION_OPTIONAL.has(k)) return null;
      continue;
    }
    if (o[k] === null) return null;
  }
  for (const k of ["v", "gate", "kind", "subject", "verdict", "request", "prev", "sig"]) if (typeof o[k] !== "string") return null;
  for (const k of ["passport", "operator", "reason"]) if (k in o && typeof o[k] !== "string") return null;
  if (!isU64(o.seq) || !isU64(o.at)) return null;
  const st = o.status, cp = o.checkpoint, pol = o.policy;
  if (st !== void 0 && !(exactObject(st, ["uri", "issued_at", "list"]) && typeof st.uri === "string" && isU64(st.issued_at) && b64Len(st.list, 32))) return null;
  if (cp !== void 0 && !(exactObject(cp, ["origin", "size", "root"]) && typeof cp.origin === "string" && isU64(cp.size) && b64Len(cp.root, 32))) return null;
  if (!(exactObject(pol, ["freshness", "audience"]) && typeof pol.audience === "string" && ["F1", "F2", "F3"].includes(pol.freshness))) return null;
  try {
    if (canonicalize(o) !== line) return null;
  } catch {
    return null;
  }
  const r = o;
  if (r.v !== DECISION_V || !b64Len(r.gate, 32) || !b64Len(r.request, 32) || !b64Len(r.sig, 64)) return null;
  if (!(r.seq === 0 && r.prev === "") && !b64Len(r.prev, 32)) return null;
  if (r.kind === "passport") {
    if (!parseName(r.subject) || r.passport !== void 0) return null;
  } else if (r.kind === "link") {
    if (!b64Len(r.subject, 32) || r.passport !== void 0 && !parseName(r.passport)) return null;
  } else return null;
  const okVerdict = r.verdict === "valid" && r.reason === void 0 || r.verdict === "invalid" && r.reason === "not_linked" && r.kind === "link" || r.verdict === "invalid" && r.reason !== void 0 && (FROZEN_REASONS.has(r.reason) || PRESENTATION_REASONS.has(r.reason));
  if (!okVerdict) return null;
  if (r.operator !== void 0 && (r.operator.length === 0 || new TextEncoder().encode(r.operator).length > 63)) return null;
  return r;
}
function decisionSigningBytes(r) {
  const { sig: _sig, ...rest } = r;
  void _sig;
  return new TextEncoder().encode(canonicalize(rest));
}
function signDecision(r, gatePublic, prevLine, sign) {
  const prev = prevLine === "" ? null : parseDecision(prevLine);
  if (prevLine !== "" && prev === null) throw new Error("the previous line is not a decision record");
  const rec = {
    ...r,
    v: DECISION_V,
    gate: jwkThumbprintEd25519(gatePublic),
    seq: prev ? prev.seq + 1 : 0,
    prev: prev ? b64uEncode(sha2563(new TextEncoder().encode(prevLine))) : ""
  };
  for (const k of Object.keys(rec)) if (rec[k] === void 0) delete rec[k];
  const line = canonicalize({ ...rec, sig: b64uEncode(sign(decisionSigningBytes(rec))) });
  if (parseDecision(line) === null) throw new Error("this record would not verify: a field is outside the vocabulary");
  return line;
}
function verifyDecisionChain(lines, gateKey, anchor) {
  const gate = jwkThumbprintEd25519(gateKey);
  let last = anchor ?? null;
  for (let index = 0; index < lines.length; index++) {
    const fail = (problem) => ({ ok: false, index, problem });
    const r = parseDecision(lines[index]);
    if (r === null) return fail("schema");
    if (r.gate !== gate) return fail("gate");
    if (!ed25519Verify(gateKey, decisionSigningBytes(r), strictB64u(r.sig))) return fail("signature");
    const wantSeq = last ? last.seq + 1 : 0;
    if (r.seq !== wantSeq) return fail("sequence");
    if (r.prev !== (last ? last.digest : "")) return fail("link");
    if (last && r.at < last.at) return fail("clock");
    last = { seq: r.seq, at: r.at, digest: b64uEncode(sha2563(new TextEncoder().encode(lines[index]))) };
  }
  return { ok: true, count: lines.length };
}
var HEAD_V = "ainra-decision-head-1";
function parseHead(line) {
  let o;
  try {
    o = JSON.parse(line);
  } catch {
    return null;
  }
  if (!exactObject(o, ["v", "gate", "seq", "at", "head", "sig"])) return null;
  for (const k of ["v", "gate", "head", "sig"]) if (typeof o[k] !== "string") return null;
  if (!isU64(o.seq) || !isU64(o.at)) return null;
  try {
    if (canonicalize(o) !== line) return null;
  } catch {
    return null;
  }
  const h = o;
  if (h.v !== HEAD_V || !b64Len(h.gate, 32) || !b64Len(h.head, 32) || !b64Len(h.sig, 64)) return null;
  return h;
}
function headSigningBytes(h) {
  const { sig: _sig, ...rest } = h;
  void _sig;
  return new TextEncoder().encode(canonicalize(rest));
}
function verifyHeadInner(line, gateKey) {
  const h = parseHead(line);
  if (h === null) throw new Reject("schema_violation");
  if (h.gate !== jwkThumbprintEd25519(gateKey)) throw new Reject("sig_invalid");
  if (!ed25519Verify(gateKey, headSigningBytes(h), strictB64u(h.sig))) throw new Reject("sig_invalid");
  return h;
}
function verifyHeadStatement(line, gateKey) {
  try {
    return { verdict: "valid", statement: verifyHeadInner(line, gateKey) };
  } catch (e) {
    if (e instanceof Reject) return { verdict: "invalid", reason: e.reason };
    return { verdict: "invalid", reason: "schema_violation" };
  }
}
function signHeadStatement(lastLine, gatePublic, sign) {
  const r = parseDecision(lastLine);
  if (r === null) throw new Error("the last line is not a decision record");
  const h = {
    v: HEAD_V,
    gate: jwkThumbprintEd25519(gatePublic),
    seq: r.seq,
    at: r.at,
    head: b64uEncode(sha2563(new TextEncoder().encode(lastLine)))
  };
  return canonicalize({ ...h, sig: b64uEncode(sign(headSigningBytes(h))) });
}
function verifyHeadReceiptInner(r, anchors, revokedDelegates, gateKey, now) {
  if (r === null || typeof r !== "object" || typeof r.statement !== "string" || typeof r.registrar !== "string") throw new Reject("schema_violation");
  const h = verifyHeadInner(r.statement, gateKey);
  if (!Object.hasOwn(anchors, r.registrar)) throw new Reject("unknown_registrar");
  const reg = anchors[r.registrar];
  if (!r.checkpoint || !isU64(r.leaf_index) || !isU64(r.checkpoint.size) || !Array.isArray(r.inclusion_proof)) throw new Reject("schema_violation");
  const cpRoot = dec(r.checkpoint.root);
  if (cpRoot.length !== 32) throw new Reject("schema_violation");
  const cpSig = decodeCheckpointSig(r.checkpoint_sig);
  const proof = r.inclusion_proof.map((x2) => {
    const b = dec(x2);
    if (b.length !== 32) throw new Reject("schema_violation");
    return b;
  });
  if (!verifyCheckpointSig(reg.logRootKey, { origin: r.checkpoint.origin, rootB64: r.checkpoint.root, size: r.checkpoint.size }, cpSig, now))
    throw new Reject("checkpoint_invalid");
  if (cpSig.mode === "delegate" && revokedDelegates.has(certFingerprintB64(cpSig.cert))) throw new Reject("checkpoint_invalid");
  if (!verifyInclusion(hashLeaf(new TextEncoder().encode(r.statement)), r.leaf_index, r.checkpoint.size, proof, cpRoot))
    throw new Reject("not_logged");
  return h;
}
function verifyDecisionChainToHead(lines, gateKey, anchor, head) {
  if (head.gate !== jwkThumbprintEd25519(gateKey)) return { ok: false, index: 0, problem: "gate" };
  const r = verifyDecisionChain(lines, gateKey, anchor);
  if (!r.ok) return r;
  const first = anchor ? anchor.seq + 1 : 0;
  if (head.seq < first) {
    if (anchor && anchor.seq === head.seq && anchor.digest !== head.head) return { ok: false, index: 0, problem: "forked" };
    return r;
  }
  const at = head.seq - first;
  if (at >= lines.length) return { ok: false, index: lines.length, problem: "truncated" };
  if (b64uEncode(sha2563(new TextEncoder().encode(lines[at]))) !== head.head) return { ok: false, index: at, problem: "forked" };
  return r;
}
function runDecisionVector(v) {
  const key = strictB64u(v.gate_key);
  if (key === null || key.length !== 32) return { ok: false, index: 0, problem: "schema" };
  if (v.anchor !== null && v.anchor !== void 0) {
    const d = strictB64u(v.anchor.digest);
    if (!isU64(v.anchor.seq) || !isU64(v.anchor.at) || d === null || d.length !== 32) return { ok: false, index: 0, problem: "schema" };
  }
  let head = null;
  if (v.receipt !== void 0 && v.receipt !== null) {
    const gate = v.directory && v.roots ? Verifier.fromDirectoryB64(v.directory, v.roots.root_ed25519, v.roots.root_slh, "F3") : null;
    if (!gate) return { ok: false, head: "unknown_registrar" };
    const hv = gate.verifyHeadReceipt(v.receipt, key, v.now ?? 0);
    if (hv.verdict === "invalid") return { ok: false, head: hv.reason };
    head = hv.statement;
  } else if (typeof v.head === "string") {
    const hv = verifyHeadStatement(v.head, key);
    if (hv.verdict === "invalid") return { ok: false, head: hv.reason };
    head = hv.statement;
  }
  return head ? verifyDecisionChainToHead(v.lines, key, v.anchor, head) : verifyDecisionChain(v.lines, key, v.anchor);
}
function decisionRequestDigest(req) {
  return b64uEncode(sha2563(new TextEncoder().encode(canonicalize({
    authority: req.authority,
    content_digest: req.contentDigest ?? "",
    method: req.method,
    path: req.path
  }))));
}
function createDecisionLog(o) {
  let last = o.lastLine ?? "";
  return {
    record(d) {
      const line = signDecision({ ...d, policy: { freshness: o.freshness, audience: o.audience ?? "" } }, o.gatePublic, last, o.sign);
      o.append(line);
      last = line;
      return line;
    },
    head() {
      return last === "" ? "" : b64uEncode(sha2563(new TextEncoder().encode(last)));
    },
    /** The signed head statement for where the log stands now (D-081) — hand it to a registrar's
     *  `POST /decision-head` with the gate's public key. `""` while the log is empty. */
    statement() {
      return last === "" ? "" : signHeadStatement(last, o.gatePublic, o.sign);
    }
  };
}

// src/conformance.ts
var conformance_exports = {};
__export(conformance_exports, {
  expectedVerdict: () => expectedVerdict,
  runCurrencyVector: () => runCurrencyVector,
  runDecisionVector: () => runDecisionVector,
  runDeltaVector: () => runDeltaVector,
  runDirectoryEpochVector: () => runDirectoryEpochVector,
  runDirectoryVector: () => runDirectoryVector,
  runGateVector: () => runGateVector,
  runLinkVector: () => runLinkVector,
  runPresentationVector: () => runPresentationVector,
  runVector: () => runVector
});
export {
  DECISION_V,
  HEAD_V,
  INSTANCE_CRED_DEFAULT_SECS,
  MAX_AGE_SECS,
  MAX_CAPABILITIES,
  MAX_FUTURE_SECS,
  MAX_IID_LEN,
  PASSPORT_VALIDITY_DEFAULT_SECS,
  POP_HEADER,
  POP_MAX_FUTURE_SECS,
  POP_MAX_SKEW_SECS,
  PRESENTATION_HEADER,
  PRIME_PATH,
  RENEWAL_LEAD_SECS,
  SIG_ALG,
  SIG_LABEL,
  Verifier,
  WIMSE_SIG_MAX_SECS,
  WIMSE_TAG,
  WIT_HEADER,
  WIT_MAX_SECS,
  WIT_TYP,
  canonicalize,
  conformance_exports as conformance,
  contentDigest,
  coveredComponents,
  createDecisionLog,
  createDirectoryHolder,
  decisionRequestDigest,
  decisionSigningBytes,
  decodeInstance,
  headHash,
  headSigningBytes,
  instanceCredDigest,
  instanceSigningBytes,
  isPresentationRef,
  joinPresentation,
  jwkThumbprintEd25519,
  jwkThumbprintEs256k,
  linkFromIndex,
  linkPopSigningBytes,
  mintInstanceCredential,
  mintWit,
  numberFromName,
  popSigningBytes,
  presentationRef,
  presentedKeyThumbprint,
  proveInstancePossession,
  renewalDue,
  serializeVerdictEvent,
  signDecision,
  signHeadStatement,
  signPresentation,
  signWimseRequest,
  signatureBase,
  splitPresentation,
  strictB64u,
  trustDomainOf,
  verdictEvent,
  verify,
  verifyDecisionChain,
  verifyDecisionChainToHead,
  verifyDelta,
  verifyDirectory,
  verifyDirectoryAtLeast,
  verifyFreshHead,
  verifyHeadStatement,
  verifyLogCheckpoint,
  verifyPresentation,
  verifyWimseRequest,
  wimseIdentifier
};
/*! Bundled license information:

@noble/hashes/esm/utils.js:
@noble/hashes/esm/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/utils.js:
@noble/curves/esm/abstract/modular.js:
@noble/curves/esm/abstract/curve.js:
@noble/curves/esm/abstract/edwards.js:
@noble/curves/esm/ed25519.js:
@noble/curves/esm/abstract/weierstrass.js:
@noble/curves/esm/_shortw_utils.js:
@noble/curves/esm/secp256k1.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/post-quantum/esm/utils.js:
@noble/post-quantum/esm/_crystals.js:
@noble/post-quantum/esm/ml-dsa.js:
@noble/post-quantum/esm/slh-dsa.js:
  (*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) *)
*/

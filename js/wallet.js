import { WORDLIST } from "./wordlist.js";

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return bytes;
}
function bigIntToBytes32(n) {
  return hexToBytes(n.toString(16).padStart(64, "0"));
}
function bytesToBigInt(bytes) {
  return BigInt("0x" + bytesToHex(bytes));
}
function concatBytes(...arrays) {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const r = new Uint8Array(total);
  let o = 0;
  for (const a of arrays) {
    r.set(a, o);
    o += a.length;
  }
  return r;
}
async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}
async function sha256d(data) {
  return sha256(await sha256(data));
}

function ripemd160(msg) {
  const RL = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6,
    15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13,
    11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9,
    7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
  ];
  const RR = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5,
    10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10,
    0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10,
    4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
  ];
  const SL = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9,
    7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13,
    6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9,
    15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
  ];
  const SR = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8,
    9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14,
    13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5,
    12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
  ];
  const KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
  function f(j, x, y, z) {
    if (j < 16) return (x ^ y ^ z) >>> 0;
    if (j < 32) return ((x & y) | (~x & z)) >>> 0;
    if (j < 48) return ((x | ~y) ^ z) >>> 0;
    if (j < 64) return ((x & z) | (y & ~z)) >>> 0;
    return (x ^ (y | ~z)) >>> 0;
  }
  function rol32(x, n) {
    return ((x << n) | (x >>> (32 - n))) >>> 0;
  }
  function add32(...a) {
    return a.reduce((s, v) => (s + v) >>> 0, 0);
  }
  if (!(msg instanceof Uint8Array)) msg = new Uint8Array(msg);
  const len = msg.length,
    bitLen = len * 8;
  const padLen = len % 64 < 56 ? 56 - (len % 64) : 120 - (len % 64);
  const padded = new Uint8Array(len + padLen + 8);
  padded.set(msg);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(len + padLen, bitLen >>> 0, true);
  dv.setUint32(len + padLen + 4, Math.floor(bitLen / 0x100000000), true);
  let h0 = 0x67452301,
    h1 = 0xefcdab89,
    h2 = 0x98badcfe,
    h3 = 0x10325476,
    h4 = 0xc3d2e1f0;
  for (let i = 0; i < padded.length; i += 64) {
    const W = new Array(16);
    for (let j = 0; j < 16; j++) W[j] = dv.getUint32(i + j * 4, true);
    let al = h0,
      bl = h1,
      cl = h2,
      dl = h3,
      el = h4,
      ar = h0,
      br = h1,
      cr = h2,
      dr = h3,
      er = h4;
    for (let j = 0; j < 80; j++) {
      let T = add32(al, f(j, bl, cl, dl), W[RL[j]], KL[Math.floor(j / 16)]);
      T = add32(rol32(T, SL[j]), el);
      al = el;
      el = dl;
      dl = rol32(cl, 10);
      cl = bl;
      bl = T;
      T = add32(ar, f(79 - j, br, cr, dr), W[RR[j]], KR[Math.floor(j / 16)]);
      T = add32(rol32(T, SR[j]), er);
      ar = er;
      er = dr;
      dr = rol32(cr, 10);
      cr = br;
      br = T;
    }
    const T = add32(h1, cl, dr);
    h1 = add32(h2, dl, er);
    h2 = add32(h3, el, ar);
    h3 = add32(h4, al, br);
    h4 = add32(h0, bl, cr);
    h0 = T;
  }
  const result = new Uint8Array(20),
    rv = new DataView(result.buffer);
  rv.setUint32(0, h0, true);
  rv.setUint32(4, h1, true);
  rv.setUint32(8, h2, true);
  rv.setUint32(12, h3, true);
  rv.setUint32(16, h4, true);
  return result;
}

async function hash160(data) {
  return ripemd160(await sha256(data));
}
async function hmacSha512(key, data) {
  const k = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}
async function pbkdf2(password, salt, iterations, keyLen) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations,
      hash: "SHA-512",
    },
    baseKey,
    keyLen * 8,
  );
  return new Uint8Array(bits);
}

function modP(n) {
  return ((n % P) + P) % P;
}
function pointAdd(pt1, pt2) {
  if (pt1 === null) return pt2;
  if (pt2 === null) return pt1;
  const [px, py] = pt1,
    [qx, qy] = pt2;
  if (px === qx) {
    if (py !== qy) return null;
    const m = modP(3n * px * px * modInverse(2n * py, P));
    const rx = modP(m * m - 2n * px);
    return [rx, modP(m * (px - rx) - py)];
  }
  const m = modP((qy - py) * modInverse(qx - px, P));
  const rx = modP(m * m - px - qx);
  return [rx, modP(m * (px - rx) - py)];
}
function modInverse(a, m) {
  a = ((a % m) + m) % m;
  let [old_r, r] = [a, m],
    [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}
function pointMul(k, pt) {
  let R = null,
    Q = pt;
  while (k > 0n) {
    if (k & 1n) R = pointAdd(R, Q);
    Q = pointAdd(Q, Q);
    k >>= 1n;
  }
  return R;
}
function privateKeyToPublicKey(privKey, compressed = true) {
  const G = [Gx, Gy];
  const [x, y] = pointMul(privKey, G);
  if (!compressed)
    return concatBytes(
      new Uint8Array([0x04]),
      bigIntToBytes32(x),
      bigIntToBytes32(y),
    );
  const prefix = (y & 1n) === 0n ? 0x02 : 0x03;
  return concatBytes(new Uint8Array([prefix]), bigIntToBytes32(x));
}

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function base58Encode(bytes) {
  let num = bytesToBigInt(bytes),
    result = "";
  while (num > 0n) {
    result = BASE58[Number(num % 58n)] + result;
    num = num / 58n;
  }
  for (const b of bytes) {
    if (b === 0) result = "1" + result;
    else break;
  }
  return result;
}
async function base58Check(payload) {
  const checksum = (await sha256d(payload)).slice(0, 4);
  return base58Encode(concatBytes(payload, checksum));
}

export function base58Decode(str) {
  let num = 0n;
  for (const ch of str) {
    const idx = BASE58.indexOf(ch);
    if (idx < 0) throw new Error("invalid base58 character: " + ch);
    num = num * 58n + BigInt(idx);
  }
  const hexStr = num.toString(16);
  const paddedHex = (hexStr.length % 2 ? "0" : "") + hexStr;
  const bigintBytes = hexToBytes(paddedHex);
  let leadingZeros = 0;
  for (const ch of str) {
    if (ch === "1") leadingZeros++;
    else break;
  }
  const result = new Uint8Array(leadingZeros + bigintBytes.length);
  result.set(bigintBytes, leadingZeros);
  return result;
}

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATOR = [
  0x3b6a57b2n,
  0x26508e6dn,
  0x1ea119fan,
  0x3d4233ddn,
  0x2a1462b3n,
];
export function bech32Polymod(values) {
  let chk = 1n;
  for (const v of values) {
    const top = chk >> 25n;
    chk = ((chk & 0x1ffffffn) << 5n) ^ BigInt(v);
    for (let i = 0; i < 5; i++) {
      if ((top >> BigInt(i)) & 1n) chk ^= BECH32_GENERATOR[i];
    }
  }
  return chk;
}
export function bech32HrpExpand(hrp) {
  const r = [];
  for (const c of hrp) r.push(c.charCodeAt(0) >> 5);
  r.push(0);
  for (const c of hrp) r.push(c.charCodeAt(0) & 31);
  return r;
}
export function convertbits(data, frombits, tobits, pad = true) {
  let acc = 0,
    bits = 0;
  const result = [],
    maxv = (1 << tobits) - 1;
  for (const value of data) {
    acc = (acc << frombits) | value;
    bits += frombits;
    while (bits >= tobits) {
      bits -= tobits;
      result.push((acc >> bits) & maxv);
    }
  }
  if (pad && bits > 0) result.push((acc << (tobits - bits)) & maxv);
  return result;
}
export function bech32Encode(hrp, data) {
  const combined = [...bech32HrpExpand(hrp), ...data];
  const checksum = bech32Polymod([...combined, 0, 0, 0, 0, 0, 0]) ^ 1n;
  let result = hrp + "1";
  for (const d of data) result += BECH32_CHARSET[d];
  for (let p = 0; p < 6; p++)
    result += BECH32_CHARSET[Number((checksum >> BigInt(5 * (5 - p))) & 31n)];
  return result;
}
const BECH32M_CONST = 0x2bc830a3n;
export function bech32mEncode(hrp, data) {
  const combined = [...bech32HrpExpand(hrp), ...data];
  const checksum =
    bech32Polymod([...combined, 0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST;
  let result = hrp + "1";
  for (const d of data) result += BECH32_CHARSET[d];
  for (let p = 0; p < 6; p++)
    result += BECH32_CHARSET[Number((checksum >> BigInt(5 * (5 - p))) & 31n)];
  return result;
}

async function pubKeyToLegacy(pubKey) {
  const h160 = await hash160(pubKey);
  return base58Check(concatBytes(new Uint8Array([0x00]), h160));
}
export async function pubKeyToSegwit(pubKey) {
  const h160 = await hash160(pubKey);
  const redeemScript = concatBytes(new Uint8Array([0x00, 0x14]), h160);
  const scriptHash = await hash160(redeemScript);
  return base58Check(concatBytes(new Uint8Array([0x05]), scriptHash));
}
async function pubKeyToNativeSegwit(pubKey) {
  const h160 = await hash160(pubKey);
  return bech32Encode("bc", [0, ...convertbits(h160, 8, 5)]);
}
function modPow(base, exp, mod) {
  let r = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return r;
}

async function pubKeyToTaproot(pubKey) {
  if (pubKey.length !== 33) throw new Error("pubkey must be 33 bytes");
  if (pubKey[0] !== 0x02 && pubKey[0] !== 0x03) {
    throw new Error("pubkey must be compressed (02/03 prefix)");
  }

  const xOnly = pubKey.slice(1);
  const x = bytesToBigInt(xOnly);
  const isOdd = pubKey[0] === 0x03;

  const x3 = (x * x * x) % P;
  const y_sq = (x3 + 7n) % P;

  let y = modPow(y_sq, (P + 1n) / 4n, P);

  if ((y & 1n) !== (isOdd ? 1n : 0n)) {
    y = P - y;
  }

  const internalPoint = [x, y];

  const tag = new TextEncoder().encode("TapTweak");
  const tagHash = await sha256(tag);
  const tweakInput = concatBytes(tagHash, tagHash, xOnly);
  const tweak = await sha256(tweakInput);
  const t = bytesToBigInt(tweak) % N;

  const G = [Gx, Gy];
  const tweakPoint = pointMul(t, G);
  const outputPoint = pointAdd(internalPoint, tweakPoint);

  if (outputPoint === null) {
    throw new Error("tweak produced point at infinity - astronomically rare");
  }

  const outputKey = bigIntToBytes32(outputPoint[0]);

  const words = [1, ...convertbits(outputKey, 8, 5)];
  return bech32mEncode("bc", words);
}

async function privateKeyToWIF(privKey, compressed = true) {
  const keyBytes = bigIntToBytes32(privKey);
  const suffix = compressed ? new Uint8Array([0x01]) : new Uint8Array([]);
  return base58Check(concatBytes(new Uint8Array([0x80]), keyBytes, suffix));
}

export async function generateMnemonic(strength = 128, extraEntropy = null) {
  if (![128, 160, 192, 224, 256].includes(strength))
    throw new Error("invalid strength");
  const csprng = crypto.getRandomValues(new Uint8Array(strength / 8));
  if (!extraEntropy || extraEntropy.length === 0)
    return entropyToMnemonic(csprng);
  const tsBuf = new Uint8Array(8);
  new DataView(tsBuf.buffer).setFloat64(0, performance.now(), false);
  const combined = concatBytes(csprng, extraEntropy, tsBuf);
  const mixed = new Uint8Array(await crypto.subtle.digest("SHA-256", combined));
  return entropyToMnemonic(mixed.slice(0, strength / 8));
}

async function entropyToMnemonic(entropy) {
  const checksum = await sha256(entropy);
  const bits = Array.from(entropy)
    .map((b) => b.toString(2).padStart(8, "0"))
    .join("");
  const checksumBits = checksum[0]
    .toString(2)
    .padStart(8, "0")
    .slice(0, entropy.length / 4);
  const allBits = bits + checksumBits;
  const words = [];
  for (let i = 0; i < allBits.length; i += 11)
    words.push(WORDLIST[parseInt(allBits.slice(i, i + 11), 2)]);
  return words.join(" ");
}

async function mnemonicToSeed(mnemonic, passphrase = "") {
  return pbkdf2(
    mnemonic.normalize("NFKD"),
    "mnemonic" + passphrase.normalize("NFKD"),
    2048,
    64,
  );
}

async function validateMnemonic(mnemonic) {
  try {
    const words = mnemonic.trim().toLowerCase().split(/\s+/);
    if (![12, 15, 18, 21, 24].includes(words.length)) return false;
    for (const word of words) if (!WORDLIST.includes(word)) return false;
    const bits = words
      .map((w) => WORDLIST.indexOf(w).toString(2).padStart(11, "0"))
      .join("");
    const dividerIndex = Math.floor(bits.length / 33) * 32;
    const entropyBits = bits.slice(0, dividerIndex);
    const checksumBits = bits.slice(dividerIndex);
    const entropyBytes = new Uint8Array(
      entropyBits.match(/.{8}/g).map((b) => parseInt(b, 2)),
    );
    const hash = await sha256(entropyBytes);
    const hashBits = Array.from(hash)
      .map((b) => b.toString(2).padStart(8, "0"))
      .join("");
    return hashBits.slice(0, checksumBits.length) === checksumBits;
  } catch {
    return false;
  }
}

async function deriveChild(parentKey, parentChainCode, index) {
  let data;
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  if (index >= 0x80000000) {
    data = concatBytes(new Uint8Array([0x00]), parentKey, indexBytes);
  } else {
    data = concatBytes(
      privateKeyToPublicKey(bytesToBigInt(parentKey)),
      indexBytes,
    );
  }
  const I = await hmacSha512(parentChainCode, data);
  const IL = I.slice(0, 32),
    IR = I.slice(32);
  const ILint = bytesToBigInt(IL);
  if (ILint >= N) throw new Error("BIP32: IL>=N (astronomically rare)");
  const childKey = (ILint + bytesToBigInt(parentKey)) % N;
  if (childKey === 0n)
    throw new Error("BIP32: child key is zero (astronomically rare)");
  return { key: bigIntToBytes32(childKey), chainCode: IR };
}
async function derivePath(seed, path) {
  const I = await hmacSha512(new TextEncoder().encode("Bitcoin seed"), seed);
  let key = I.slice(0, 32),
    chainCode = I.slice(32);
  for (const part of path.replace("m/", "").split("/")) {
    const hardened = part.endsWith("'");
    const index = parseInt(part) + (hardened ? 0x80000000 : 0);
    const child = await deriveChild(key, chainCode, index);
    key = child.key;
    chainCode = child.chainCode;
  }
  return { key, chainCode };
}

export const WALLET_TYPES = {
  LEGACY: {
    name: "Legacy (P2PKH)",
    prefix: "1",
    path: "m/44'/0'/0'/0/0",
    color: "#f7931a",
  },
  SEGWIT: {
    name: "SegWit (P2SH)",
    prefix: "3",
    path: "m/49'/0'/0'/0/0",
    color: "#00d4aa",
  },
  NATIVE_SEGWIT: {
    name: "Native SegWit (Bech32)",
    prefix: "bc1q",
    path: "m/84'/0'/0'/0/0",
    color: "#7c3aed",
  },
  TAPROOT: {
    name: "Taproot (P2TR)",
    prefix: "bc1p",
    path: "m/86'/0'/0'/0/0",
    color: "#f97316",
  },
};

async function generateWalletFromMnemonic(
  mnemonic,
  passphrase = "",
  walletType = "LEGACY",
  accountIndex = 0,
  addressIndex = 0,
) {
  const seed = await mnemonicToSeed(mnemonic, passphrase);
  const purpose =
    walletType === "LEGACY"
      ? "44'"
      : walletType === "SEGWIT"
        ? "49'"
        : walletType === "TAPROOT"
          ? "86'"
          : "84'";
  const path = `m/${purpose}/0'/${accountIndex}'/0/${addressIndex}`;
  const { key } = await derivePath(seed, path);
  const privKeyBigInt = bytesToBigInt(key);
  const pubKey = privateKeyToPublicKey(privKeyBigInt);
  let address;
  if (walletType === "LEGACY") address = await pubKeyToLegacy(pubKey);
  else if (walletType === "SEGWIT") address = await pubKeyToSegwit(pubKey);
  else if (walletType === "TAPROOT") address = await pubKeyToTaproot(pubKey);
  else address = await pubKeyToNativeSegwit(pubKey);
  return {
    mnemonic,
    passphrase: passphrase ? "(custom passphrase set)" : "",
    path,
    privateKeyHex: bytesToHex(key),
    privateKeyWIF: await privateKeyToWIF(privKeyBigInt, true),
    publicKeyHex: bytesToHex(pubKey),
    address: await address,
    walletType,
    typeName: WALLET_TYPES[walletType].name,
  };
}

export async function generateRandomWallet(
  walletType = "LEGACY",
  wordCount = 12,
  passphrase = "",
  extraEntropy = null,
) {
  const mnemonic = await generateMnemonic(
    wordCount === 24 ? 256 : 128,
    extraEntropy,
  );
  return generateWalletFromMnemonic(mnemonic, passphrase, walletType);
}

async function deriveMultipleAddresses(
  mnemonic,
  passphrase = "",
  walletType = "LEGACY",
  count = 5,
  branch = 0,
  accountIndex = 0,
  customPath = null,
  startIndex = 0,
) {
  const seed = await mnemonicToSeed(mnemonic, passphrase);
  const purpose =
    walletType === "LEGACY"
      ? "44'"
      : walletType === "SEGWIT"
        ? "49'"
        : walletType === "TAPROOT"
          ? "86'"
          : "84'";
  const addresses = [];
  for (let i = 0; i < count; i++) {
    const addrIndex = startIndex + i;
    let path;
    if (customPath && customPath.trim()) {
      const basePath = customPath.trim().replace(/\/\d+$/, "");
      const segments = basePath.replace("m/", "").split("/").length;
      if (segments < 4)
        throw new Error(
          "Custom path too short, expected at least m/purpose/coin/account/branch",
        );
      path = basePath + `/${addrIndex}`;
    } else {
      path = `m/${purpose}/0'/${accountIndex}'/${branch}/${addrIndex}`;
    }
    const { key } = await derivePath(seed, path);
    const privKeyBigInt = bytesToBigInt(key);
    const pubKey = privateKeyToPublicKey(privKeyBigInt);
    let address;
    if (walletType === "LEGACY") address = await pubKeyToLegacy(pubKey);
    else if (walletType === "SEGWIT") address = await pubKeyToSegwit(pubKey);
    else if (walletType === "TAPROOT") address = await pubKeyToTaproot(pubKey);
    else address = await pubKeyToNativeSegwit(pubKey);
    addresses.push({
      index: addrIndex,
      path,
      address: await address,
      privateKeyWIF: await privateKeyToWIF(privKeyBigInt, true),
    });
  }
  return addresses;
}

async function validateRoundTrip(wallet) {
  const errors = [];
  try {
    const decoded = base58Decode(wallet.privateKeyWIF);

    if (decoded.length !== 37 && decoded.length !== 38) {
      errors.push(
        `WIF decoded to unexpected length: ${decoded.length} bytes (expected 37 or 38)`,
      );
      return { valid: false, errors };
    }
    if (decoded[0] !== 0x80) {
      errors.push(
        "WIF version byte invalid (expected 0x80, got 0x" +
          decoded[0].toString(16) +
          ")",
      );
      return { valid: false, errors };
    }
    const isCompressed = decoded.length === 38;
    if (isCompressed && decoded[33] !== 0x01) {
      errors.push(
        "WIF compression flag byte invalid (expected 0x01, got 0x" +
          decoded[33].toString(16) +
          ")",
      );
      return { valid: false, errors };
    }
    const payload = decoded.slice(0, decoded.length - 4);
    const storedCS = decoded.slice(-4);
    const computedCS = (await sha256d(payload)).slice(0, 4);
    for (let i = 0; i < 4; i++) {
      if (storedCS[i] !== computedCS[i]) {
        errors.push("WIF checksum mismatch - key may be corrupted");
        return { valid: false, errors };
      }
    }
    const keyBytes = decoded.slice(1, 33);
    const privKeyBigInt = bytesToBigInt(keyBytes);
    if (privKeyBigInt === 0n || privKeyBigInt >= N) {
      errors.push("decoded private key is outside valid secp256k1 range");
      return { valid: false, errors };
    }
    const pubKey = privateKeyToPublicKey(privKeyBigInt);
    let rederived;
    if (wallet.walletType === "LEGACY")
      rederived = await pubKeyToLegacy(pubKey);
    else if (wallet.walletType === "SEGWIT")
      rederived = await pubKeyToSegwit(pubKey);
    else if (wallet.walletType === "TAPROOT")
      rederived = await pubKeyToTaproot(pubKey);
    else rederived = await pubKeyToNativeSegwit(pubKey);
    if (rederived !== wallet.address) {
      errors.push("ADDRESS MISMATCH - derivation inconsistency detected");
      errors.push(`  stored:    ${wallet.address}`);
      errors.push(`  rederived: ${rederived}`);
    }
  } catch (e) {
    errors.push("round-trip validation threw: " + e.message);
  }

  const prefixOk =
    (wallet.walletType === "LEGACY" && wallet.address.startsWith("1")) ||
    (wallet.walletType === "SEGWIT" && wallet.address.startsWith("3")) ||
    (wallet.walletType === "NATIVE_SEGWIT" &&
      wallet.address.startsWith("bc1q")) ||
    (wallet.walletType === "TAPROOT" && wallet.address.startsWith("bc1p"));
  if (!prefixOk) errors.push("address prefix does not match wallet type");
  if (wallet.mnemonic && !(await validateMnemonic(wallet.mnemonic)))
    errors.push("mnemonic BIP39 checksum invalid");
  if (wallet.privateKeyWIF.length < 51 || wallet.privateKeyWIF.length > 53)
    errors.push(`WIF length suspicious: ${wallet.privateKeyWIF.length} chars`);
  return { valid: errors.length === 0, errors };
}

export function secureWipe(obj) {
  if (typeof obj !== "object" || obj === null) return;
  const zeros = "0".repeat(64);
  for (const key in obj) {
    const v = obj[key];
    if (typeof v === "string")
      obj[key] = zeros.repeat(Math.ceil(v.length / 64)).slice(0, v.length);
    else if (v instanceof Uint8Array || v instanceof Uint32Array) v.fill(0);
    else if (typeof v === "bigint") obj[key] = 0n;
    else if (Array.isArray(v)) {
      v.forEach((item) => secureWipe(item));
      v.length = 0;
    }
  }
  for (const key in obj) obj[key] = null;
  try {
    if (typeof window !== "undefined" && typeof window.gc === "function")
      window.gc();
  } catch (_) {}
}

function bech32Verify(addr) {
  if (!addr.startsWith("bc1q")) return false;
  const hrp = addr.slice(0, 2);
  const dataPart = addr.slice(3);
  const values = Array.from(dataPart).map((ch) => BECH32_CHARSET.indexOf(ch));
  if (values.some((v) => v === -1)) return false;
  const data = values.slice(0, -6);
  const checksum = values.slice(-6);
  const combined = [...bech32HrpExpand(hrp), ...data];
  const expected = bech32Polymod([...combined, 0, 0, 0, 0, 0, 0]) ^ 1n;
  let expArr = [];
  for (let i = 0; i < 6; i++)
    expArr.push(Number((expected >> BigInt(5 * (5 - i))) & 31n));
  if (!checksum.every((c, i) => c === expArr[i])) return false;
  const ver = data[0];
  if (ver !== 0) return false;
  return true;
}

function bech32mVerify(addr) {
  if (!addr.startsWith("bc1p")) return false;
  const hrp = addr.slice(0, 2);
  const dataPart = addr.slice(3);
  const values = Array.from(dataPart).map((ch) => BECH32_CHARSET.indexOf(ch));
  if (values.some((v) => v === -1)) return false;
  const data = values.slice(0, -6);
  const checksum = values.slice(-6);
  const combined = [...bech32HrpExpand(hrp), ...data];
  const expected =
    bech32Polymod([...combined, 0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST;
  let expArr = [];
  for (let i = 0; i < 6; i++)
    expArr.push(Number((expected >> BigInt(5 * (5 - i))) & 31n));
  if (!checksum.every((c, i) => c === expArr[i])) return false;
  const ver = data[0];
  if (ver !== 1) return false;
  return true;
}

async function validateBitcoinAddress(addr) {
  try {
    const decoded = base58Decode(addr);

    if (addr[0] === "1") {
      if (decoded.length !== 25)
        return { valid: false, reason: "wrong length" };
      if (decoded[0] !== 0x00)
        return { valid: false, reason: "invalid version byte" };
      const payload = decoded.slice(0, 21);
      const checksum = decoded.slice(21);
      const computed = (await sha256d(payload)).slice(0, 4);
      const checksumOk = checksum.every((b, i) => b === computed[i]);
      if (!checksumOk) return { valid: false, reason: "checksum mismatch" };
      return {
        valid: true,
        type: "Legacy P2PKH",
        note: "Base58Check passed",
      };
    } else if (addr[0] === "3") {
      if (decoded.length !== 25)
        return { valid: false, reason: "wrong length" };
      if (decoded[0] !== 0x05)
        return { valid: false, reason: "invalid version byte" };
      const payload = decoded.slice(0, 21);
      const checksum = decoded.slice(21);
      const computed = (await sha256d(payload)).slice(0, 4);
      const checksumOk = checksum.every((b, i) => b === computed[i]);
      if (!checksumOk) return { valid: false, reason: "checksum mismatch" };
      return {
        valid: true,
        type: "SegWit P2SH",
        note: "Base58Check passed",
      };
    } else if (addr.startsWith("bc1q")) {
      if (bech32Verify(addr)) {
        return {
          valid: true,
          type: "Native SegWit (Bech32)",
          note: "Bech32 checksum ok",
        };
      }
      return { valid: false, reason: "invalid Bech32 address" };
    } else if (addr.startsWith("bc1p")) {
      if (bech32mVerify(addr)) {
        return {
          valid: true,
          type: "Taproot (Bech32m)",
          note: "Bech32m checksum ok",
        };
      }
      return { valid: false, reason: "invalid Bech32m address" };
    } else {
      return { valid: false, reason: "unknown address type" };
    }
  } catch (e) {
    return { valid: false, reason: e.message };
  }
}

function diceToEntropy(diceString) {
  const rolls = diceString
    .trim()
    .split(/[\s,;.|\-]+/)
    .map(Number)
    .filter((n) => Number.isInteger(n) && n >= 1 && n <= 6);
  if (rolls.length < 99)
    throw new Error(
      `need at least 99 dice rolls for 128-bit security, got ${rolls.length}.`,
    );
  let n = 0n;
  for (const r of rolls) n = n * 6n + BigInt(r - 1);
  const bytes = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return bytes;
}
function validateDiceInput(diceString) {
  const rolls = diceString
    .trim()
    .split(/[\s,;.|\-]+/)
    .map(Number)
    .filter((n) => Number.isInteger(n) && n >= 1 && n <= 6);
  return {
    count: rolls.length,
    valid: rolls.length >= 99,
    entropyBits: Math.floor(rolls.length * Math.log2(6)),
  };
}

async function generateMnemonicWithDice(
  diceString,
  wordCount = 12,
  walletIndex = 0,
  deterministic = false,
) {
  const strength = wordCount === 24 ? 32 : 16;
  const dice = diceToEntropy(diceString);
  if (deterministic) {
    const indexBuf = new Uint8Array(4);
    new DataView(indexBuf.buffer).setUint32(0, walletIndex, false);
    const combined = new Uint8Array(strength + 1 + 4);
    combined.set(dice.slice(0, strength), 0);
    combined[strength] = 0x00;
    combined.set(indexBuf, strength + 1);
    const mixed = new Uint8Array(
      await crypto.subtle.digest("SHA-256", combined),
    );
    return entropyToMnemonic(mixed.slice(0, strength));
  }
  const csrng = crypto.getRandomValues(new Uint8Array(strength));
  const indexBuf = new Uint8Array(4);
  new DataView(indexBuf.buffer).setUint32(0, walletIndex, false);
  const combined = new Uint8Array(strength + strength + 4);
  combined.set(csrng, 0);
  combined.set(dice.slice(0, strength), strength);
  combined.set(indexBuf, strength * 2);
  const mixed = new Uint8Array(await crypto.subtle.digest("SHA-256", combined));
  return entropyToMnemonic(mixed.slice(0, strength));
}

async function generateMnemonicFromString(inputString, wordCount = 24) {
  if (!inputString || inputString.length === 0)
    throw new Error("input string cannot be empty");
  const strength = wordCount === 24 ? 32 : 16;
  const encoded = new TextEncoder().encode(inputString);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", encoded));
  return entropyToMnemonic(hash.slice(0, strength));
}

export function secureWipeAll(walletsArray) {
  if (Array.isArray(walletsArray)) {
    walletsArray.forEach((w) => secureWipe(w));
    walletsArray.length = 0;
  }
  if (typeof document !== "undefined") {
    const sensitive = [
      "results-area",
      "print-area",
      "verify-mnemonic",
      "dice-input",
      "passphrase",
      "passphrase-confirm",
      "import-passphrase",
      "hd-passphrase",
      "string-input",
    ];
    sensitive.forEach((id) => {
      const el = document.getElementById(id);
      if (!el) return;
      if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") el.value = "";
      else el.innerHTML = "";
    });
    const ppConfirmWrapEl = document.getElementById("passphrase-confirm-wrap");
    if (ppConfirmWrapEl) ppConfirmWrapEl.style.display = "none";
    const ppMatchMsgEl = document.getElementById("passphrase-match-msg");
    if (ppMatchMsgEl) ppMatchMsgEl.textContent = "";
  }
}

if (typeof window !== "undefined") {
  function updateNetworkStatus() {
    const dot = document.getElementById("net-dot"),
      label = document.getElementById("net-label");
    const onlineAlert = document.getElementById("online-alert"),
      offlineAlert = document.getElementById("offline-ok-alert");
    if (navigator.onLine) {
      dot.className = "status-dot online";
      label.textContent = "ONLINE - UNSAFE";
      label.style.color = "var(--red)";
      onlineAlert.classList.remove("hidden");
      offlineAlert.style.display = "none";
    } else {
      dot.className = "status-dot offline";
      label.textContent = "OFFLINE - SAFE";
      label.style.color = "var(--green)";
      onlineAlert.classList.add("hidden");
      offlineAlert.style.display = "flex";
    }
    const chkOffline = document.getElementById("chk-offline");
    if (chkOffline) {
      const ok = !navigator.onLine;
      chkOffline.innerHTML = `<span class="chk-icon ${ok ? "text-green" : "text-red"}">${ok ? "✓" : "✗"}</span> Disconnected from internet`;
    }
  }
  window.addEventListener("online", updateNetworkStatus);
  window.addEventListener("offline", updateNetworkStatus);
  updateNetworkStatus();

  let entropyMode = "mouse",
    diceValid = false,
    diceDeterministic = false;

  function setEntropyMode(mode) {
    entropyMode = mode;
    ["mouse", "dice", "string"].forEach((m) => {
      document.getElementById("panel-" + m).classList.add("hidden");
      const btn = document.getElementById("mode-" + m);
      btn.style.background = "transparent";
      btn.style.color = "var(--text-dim)";
    });
    document.getElementById("panel-" + mode).classList.remove("hidden");
    const activeBtn = document.getElementById("mode-" + mode);
    activeBtn.style.background = "rgba(0,255,65,0.1)";
    activeBtn.style.color = "var(--green)";
  }

  ["mouse", "dice", "string"].forEach((m) => {
    document.getElementById("mode-" + m).addEventListener("click", () => {
      setEntropyMode(m);
      if (generatedWallets.length > 0) {
        const note = document.getElementById("entropy-mode-change-note");
        if (note) note.style.display = "block";
      }
    });
  });

  document.getElementById("dice-mode-mixed").addEventListener("click", () => {
    diceDeterministic = false;
    document.getElementById("dice-mode-mixed").style.background =
      "rgba(0,255,65,0.1)";
    document.getElementById("dice-mode-mixed").style.color = "var(--green)";
    document.getElementById("dice-mode-det").style.background = "transparent";
    document.getElementById("dice-mode-det").style.color = "var(--text-dim)";
    document.getElementById("dice-det-warning").classList.add("hidden");
    document.getElementById("dice-mode-desc").textContent =
      "Mixed: dice + CSPRNG - different wallet every run";
    updateDiceStats();
  });
  document.getElementById("dice-mode-det").addEventListener("click", () => {
    diceDeterministic = true;
    document.getElementById("dice-mode-det").style.background =
      "rgba(0,255,65,0.1)";
    document.getElementById("dice-mode-det").style.color = "var(--green)";
    document.getElementById("dice-mode-mixed").style.background = "transparent";
    document.getElementById("dice-mode-mixed").style.color = "var(--text-dim)";
    document.getElementById("dice-det-warning").classList.remove("hidden");
    document.getElementById("dice-mode-desc").textContent =
      "Deterministic: dice only - same rolls = same wallet always";
    document.getElementById("entropy-status").textContent =
      "🔒 DICE: DETERMINISTIC";
    updateDiceStats();
  });

  let stringVisible = false;
  document
    .getElementById("string-visibility-toggle")
    .addEventListener("click", () => {
      stringVisible = !stringVisible;
      document.getElementById("string-input").style.webkitTextSecurity =
        stringVisible ? "none" : "disc";
      document.getElementById("string-visibility-toggle").textContent =
        stringVisible ? "👁 HIDE" : "👁 SHOW";
    });
  document.getElementById("string-input").addEventListener("input", (e) => {
    const val = e.target.value,
      len = val.length;
    const byteLen = new TextEncoder().encode(val).length;
    const countEl = document.getElementById("string-char-count");
    if (countEl)
      countEl.textContent =
        byteLen === len ? `${len} chars` : `${len} chars · ${byteLen} bytes`;
    const byteCountEl = document.getElementById("string-byte-count");
    if (byteCountEl)
      byteCountEl.textContent =
        byteLen !== len
          ? `multi-byte chars (${byteLen} UTF-8 bytes hashed)`
          : "";
    const bar = document.getElementById("string-strength-bar"),
      lbl = document.getElementById("string-strength-label");
    const est = document.getElementById("string-entropy-estimate");
    const charsetSize = /[A-Z]/.test(val)
      ? /[0-9]/.test(val)
        ? /[^a-zA-Z0-9]/.test(val)
          ? 95
          : 62
        : 52
      : /[0-9]/.test(val)
        ? 36
        : 26;
    const estimatedBits = Math.floor(len * Math.log2(charsetSize));
    est.textContent = `~${estimatedBits} bits`;
    if (len === 0) {
      bar.style.width = "0%";
      bar.style.background = "var(--red)";
      lbl.textContent = "type your string above";
      lbl.style.color = "var(--text-muted)";
    } else if (len < 20) {
      bar.style.width = `${(len / 50) * 30}%`;
      bar.style.background = "var(--red)";
      lbl.textContent = `too short - dangerously weak (${len} chars)`;
      lbl.style.color = "var(--red)";
    } else if (len < 40) {
      bar.style.width = `${(len / 50) * 60}%`;
      bar.style.background = "var(--yellow)";
      lbl.textContent = `△ marginal - longer is safer (${len} chars)`;
      lbl.style.color = "var(--yellow)";
    } else if (len < 50) {
      bar.style.width = "80%";
      bar.style.background = "var(--yellow)";
      lbl.textContent = `△ getting better - aim for 50+ chars (${len} chars)`;
      lbl.style.color = "var(--yellow)";
    } else {
      bar.style.width = "100%";
      bar.style.background = "var(--green)";
      lbl.textContent = `✓ length acceptable - security depends entirely on unpredictability (${len} chars)`;
      lbl.style.color = "var(--green)";
    }
  });

  const bar = document.getElementById("entropy-bar"),
    entropyLabel = document.getElementById("entropy-label");
  let entropyCount = 0,
    entropyReady = false;
  const ENTROPY_TARGET = 100;
  let mouseEntropySamples = [];
  function onMouseMove(e) {
    if (entropyCount >= ENTROPY_TARGET) return;
    entropyCount++;
    mouseEntropySamples.push(
      ((e.clientX & 0xffff) << 16) | (e.clientY & 0xffff),
      Date.now() * 1000000 + Math.round(performance.now() * 1000),
    );
    const pct = Math.min(100, (entropyCount / ENTROPY_TARGET) * 100);
    bar.style.width = pct + "%";
    if (entropyCount >= ENTROPY_TARGET) {
      entropyLabel.textContent = "✓ Entropy collected - ready to generate";
      entropyLabel.style.color = "var(--green)";
      document.getElementById("entropy-status").textContent =
        "⚡ ENTROPY: COLLECTED";
      document.removeEventListener("mousemove", onMouseMove);
      entropyReady = true;
    } else {
      entropyLabel.textContent = `Collecting... ${Math.round(pct)}% (move your mouse)`;
    }
  }
  document.addEventListener("mousemove", onMouseMove, { passive: true });
  setTimeout(() => {
    if (!entropyReady) {
      entropyReady = true;
      bar.style.width = "100%";
      entropyLabel.textContent =
        entropyCount === 0
          ? "No mouse movement detected - using CSPRNG only (still secure)"
          : "Entropy ready";
      entropyLabel.style.color =
        entropyCount === 0 ? "var(--yellow)" : "var(--green)";
    }
  }, 3000);

  const diceInput = document.getElementById("dice-input");
  function updateDiceStats() {
    const val = diceInput.value;
    const info = validateDiceInput(val);
    document.getElementById("dice-count").textContent = `Rolls: ${info.count}`;
    document.getElementById("dice-entropy-bits").textContent =
      `Entropy: ~${info.entropyBits} bits`;
    const statusEl = document.getElementById("dice-status");
    if (info.valid) {
      statusEl.textContent = diceDeterministic
        ? `✓ ${info.count} rolls - deterministic entropy ready`
        : "✓ Sufficient entropy";
      statusEl.style.color = "var(--green)";
      diceValid = true;
      document.getElementById("entropy-status").textContent = diceDeterministic
        ? "🔒 DICE: DETERMINISTIC"
        : "🎲 DICE: READY";
    } else {
      statusEl.textContent = `Need ${99 - info.count} more rolls`;
      statusEl.style.color = "var(--red)";
      diceValid = false;
    }
    const rolls = val
      .trim()
      .split(/[\s,;.|\-]+/)
      .map(Number)
      .filter((n) => n >= 1 && n <= 6);
    const dist = document.getElementById("dice-distribution");
    const counts = [0, 0, 0, 0, 0, 0];
    rolls.forEach((r) => counts[r - 1]++);
    const maxCount = Math.max(...counts, 1);
    dist.innerHTML = [1, 2, 3, 4, 5, 6]
      .map((face, i) => {
        const pct = Math.round((counts[i] / maxCount) * 100);
        const expected = rolls.length > 0 ? Math.round(rolls.length / 6) : 0;
        const bias =
          expected > 0 ? Math.abs(counts[i] - expected) / expected : 0;
        const barColor = bias > 0.3 ? "var(--yellow)" : "var(--green-dim)";
        return `<div style="text-align:center;"><div style="font-size:10px;color:var(--text-muted);margin-bottom:3px;">⚅${face}</div><div style="background:var(--bg3);border:1px solid var(--border);border-radius:2px;height:40px;position:relative;overflow:hidden;"><div style="position:absolute;bottom:0;width:100%;height:${pct}%;background:${barColor};transition:height 0.2s;"></div></div><div style="font-size:10px;color:var(--text-muted);margin-top:2px;">${counts[i]}</div></div>`;
      })
      .join("");
  }

  diceInput.addEventListener("keydown", (e) => {
    if (
      e.ctrlKey ||
      e.metaKey ||
      [
        "Backspace",
        "Delete",
        "ArrowLeft",
        "ArrowRight",
        "Tab",
        "Enter",
        "Home",
        "End",
      ].includes(e.key)
    )
      return;
    if (!/^[1-6]$/.test(e.key)) {
      e.preventDefault();
      return;
    }
    e.preventDefault();
    const start = diceInput.selectionStart,
      end = diceInput.selectionEnd;
    const insert = e.key + " ";
    diceInput.value =
      diceInput.value.slice(0, start) + insert + diceInput.value.slice(end);
    diceInput.selectionStart = diceInput.selectionEnd = start + insert.length;
    document.getElementById("roll-for-me-warn").classList.add("hidden");
    updateDiceStats();
  });
  diceInput.addEventListener("paste", (e) => {
    e.preventDefault();
    const text = (e.clipboardData || window.clipboardData).getData("text");
    const digits = text.split("").filter((c) => /[1-6]/.test(c));
    const lines = [];
    for (let i = 0; i < digits.length; i += 10)
      lines.push(digits.slice(i, i + 10).join(" "));
    const start = diceInput.selectionStart;
    diceInput.value =
      diceInput.value.slice(0, start) +
      lines.join("\n") +
      diceInput.value.slice(diceInput.selectionEnd);
    document.getElementById("roll-for-me-warn").classList.add("hidden");
    updateDiceStats();
  });
  diceInput.addEventListener("input", () => {
    const raw = diceInput.value;
    if (/[^1-6 \n]/.test(raw)) {
      const digits = raw.split("").filter((c) => /[1-6]/.test(c));
      const lines = [];
      for (let i = 0; i < digits.length; i += 10)
        lines.push(digits.slice(i, i + 10).join(" "));
      diceInput.value = lines.join("\n");
    }
    document.getElementById("roll-for-me-warn").classList.add("hidden");
    updateDiceStats();
  });
  updateDiceStats();

  document.getElementById("btn-roll-for-me").addEventListener("click", () => {
    const count =
      100 +
      Math.floor((crypto.getRandomValues(new Uint8Array(1))[0] / 255) * 200);
    const rolls = [];
    while (rolls.length < count) {
      const buf = crypto.getRandomValues(
        new Uint8Array(Math.ceil((count - rolls.length) * 1.5)),
      );
      for (const b of buf) {
        if (b < 252) {
          rolls.push((b % 6) + 1);
          if (rolls.length >= count) break;
        }
      }
    }
    const lines = [];
    for (let i = 0; i < rolls.length; i += 10)
      lines.push(rolls.slice(i, i + 10).join(" "));
    diceInput.value = lines.join("\n");
    document.getElementById("roll-for-me-warn").classList.remove("hidden");
    updateDiceStats();
  });

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document
        .querySelectorAll(".tab")
        .forEach((t) => t.classList.remove("active"));
      document
        .querySelectorAll(".tab-content")
        .forEach((c) => c.classList.add("hidden"));
      tab.classList.add("active");
      document
        .getElementById("tab-" + tab.dataset.tab)
        .classList.remove("hidden");
    });
  });

  function makePassphraseToggle(inputId, btnId) {
    const btn = document.getElementById(btnId),
      inp = document.getElementById(inputId);
    if (!btn || !inp) return;
    btn.addEventListener("click", () => {
      const showing = inp.type === "text";
      inp.type = showing ? "password" : "text";
      btn.textContent = showing ? "👁" : "🙈";
    });
  }
  makePassphraseToggle("passphrase", "passphrase-toggle");
  makePassphraseToggle("passphrase-confirm", "passphrase-confirm-toggle");
  makePassphraseToggle("import-passphrase", "import-passphrase-toggle");
  makePassphraseToggle("hd-passphrase", "hd-passphrase-toggle");

  const ppField = document.getElementById("passphrase");
  const ppConfirmWrap = document.getElementById("passphrase-confirm-wrap");
  const ppConfirm = document.getElementById("passphrase-confirm");
  const ppMatchMsg = document.getElementById("passphrase-match-msg");
  function checkPassphraseMatch() {
    const a = ppField.value,
      b = ppConfirm.value;
    if (!b) {
      ppMatchMsg.textContent = "";
      return;
    }
    if (a === b) {
      ppMatchMsg.style.color = "var(--green)";
      ppMatchMsg.textContent = "✓ passphrases match";
    } else {
      ppMatchMsg.style.color = "var(--red)";
      ppMatchMsg.textContent = "passphrases do not match - typo risk!";
    }
  }
  ppField.addEventListener("input", () => {
    ppConfirmWrap.style.display = ppField.value ? "block" : "none";
    if (!ppField.value) {
      ppConfirm.value = "";
      ppMatchMsg.textContent = "";
    }
    checkPassphraseMatch();
  });
  ppConfirm.addEventListener("input", checkPassphraseMatch);

  function toast(msg, type = "success") {
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    const icon = type === "success" ? "✓" : type === "error" ? "✗" : "⚠";
    el.innerHTML = `<span>${icon}</span><span>${msg}</span>`;
    document.getElementById("toast-container").appendChild(el);
    setTimeout(() => el.remove(), 3000);
  }

  async function copyText(text, btn) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.cssText =
          "position:fixed;top:0;left:0;opacity:0;pointer-events:none;";
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      btn.textContent = "copied";
      btn.classList.add("copied");
      setTimeout(() => {
        btn.textContent = "copy";
        btn.classList.remove("copied");
      }, 1500);
    } catch {
      toast("copy failed - select text manually", "error");
    }
  }

  function renderQR(text, canvas, size = 160) {
    try {
      window.QRCode.generate(text, canvas, size);
    } catch (e) {
      console.warn("QR error:", e);
    }
  }

  function walletTypeClass(type) {
    return type === "LEGACY"
      ? "legacy"
      : type === "SEGWIT"
        ? "segwit"
        : type === "TAPROOT"
          ? "taproot"
          : "native";
  }

  function createInlineQRButton(text, label, isPrivate) {
    const btn = document.createElement("button");
    btn.className = "copy-btn qr-inline-btn";
    btn.textContent = "QR";
    let popover = null;

    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (popover) {
        popover.remove();
        popover = null;
        btn.textContent = "QR";
        btn.classList.remove("active");
        return;
      }
      document.querySelectorAll(".qr-popover-open").forEach((p) => {
        p.remove();
        const prevBtn = document.querySelector(".qr-inline-btn.active");
        if (prevBtn) {
          prevBtn.textContent = "QR";
          prevBtn.classList.remove("active");
        }
      });

      popover = document.createElement("div");
      popover.className = "qr-popover-open";

      const btnRect = btn.getBoundingClientRect();
      const popWidth = 200;
      let leftPos = btnRect.left;
      if (leftPos + popWidth > window.innerWidth - 8) {
        leftPos = window.innerWidth - popWidth - 8;
      }

      popover.style.cssText = `
                position:fixed;
                z-index:9000;
                background:#1a1a1a;
                border-radius:6px;
                padding:14px;
                box-shadow:0 8px 40px rgba(0,0,0,0.85);
                display:flex;flex-direction:column;align-items:center;gap:8px;
                border:2px solid ${isPrivate ? "#ff3333" : "#00ff41"};
                min-width:${popWidth}px;
                left:${leftPos + 35}px;
                top:${Math.min(btnRect.bottom + 6, window.innerHeight - 240)}px;
              `;

      const lbl = document.createElement("div");
      lbl.style.cssText =
        "font-size:10px;color:#aaa;font-family:var(--font-mono);letter-spacing:1px;text-transform:uppercase;font-weight:600;text-align:center;margin-bottom:2px;";

      lbl.textContent = label;
      const canvas = document.createElement("canvas");
      canvas.className = "qr";

      popover.appendChild(lbl);

      const canvasWrap = document.createElement("div");
      canvasWrap.style.cssText =
        "background:#fff;padding:8px;border-radius:3px;";
      canvasWrap.appendChild(canvas);
      popover.appendChild(canvasWrap);

      document.body.appendChild(popover);
      renderQR(text, canvas, 180);
      btn.textContent = "QR";
      btn.classList.add("active");

      const closeHandler = (ev) => {
        if (!popover.contains(ev.target) && ev.target !== btn) {
          popover.remove();
          popover = null;
          btn.textContent = "QR";
          btn.classList.remove("active");
          document.removeEventListener("click", closeHandler);
        }
      };
      setTimeout(() => document.addEventListener("click", closeHandler), 0);
    });
    return btn;
  }

  function renderWalletCard(w, index) {
    const cls = walletTypeClass(w.walletType);
    const div = document.createElement("div");
    div.className = "wallet-card";
    const mnemonicWords = w.mnemonic.split(" ");
    const wordCount = mnemonicWords.length;
    const cols = wordCount === 24 ? 6 : 6;

    div.innerHTML = `
                <div class="wallet-type-badge badge-${cls}">${w.typeName} - #${index + 1}</div>
                <div class="wallet-fields">
                  <div class="field-group">
                    <div class="field-label">Receiving Address (PUBLIC - safe to share)</div>
                    <div class="field-value address" id="fv-addr-${index}">
                      <span>${w.address}</span>
                      <div style="display:flex;gap:4px;flex-shrink:0;">
                        <button class="copy-btn" data-copy="${w.address}">copy</button>
                        <span id="qr-addr-slot-${index}"></span>
                      </div>
                    </div>
                  </div>
                  <div class="field-group">
                    <div class="field-label">Private Key WIF (KEEP SECRET - never share)</div>
                    <div class="field-value wif" id="fv-wif-${index}">
                      <span>${w.privateKeyWIF}</span>
                      <div style="display:flex;gap:4px;flex-shrink:0;">
                        <button class="copy-btn" data-copy="${w.privateKeyWIF}">copy</button>
                        <span id="qr-wif-slot-${index}"></span>
                      </div>
                    </div>
                  </div>
                  <div class="field-group">
                    <div class="field-label" style="display:flex;align-items:center;justify-content:space-between;">
                      <span>Seed Phrase - BIP39 Mnemonic (${wordCount} words)</span>
                      <div style="display:flex;gap:6px;align-items:center;">
                        <button class="copy-btn copy-mnemonic-btn" data-mnemonic="${w.mnemonic}" style="font-size:10px;padding:3px 10px;">⎘ copy words</button>
                        <span id="qr-seed-slot-${index}"></span>
                      </div>
                    </div>
                    <div class="field-value mnemonic" id="fv-seed-${index}">
                      <div style="display:grid;grid-template-columns:repeat(${cols},1fr);gap:6px;">
                        ${mnemonicWords.map((word, i) => `<span class="word-chip"><span class="word-num">${i + 1}</span><span class="word-text">${word}</span></span>`).join("")}
                      </div>
                    </div>
                  </div>
                  <div class="field-group">
                    <div class="field-label">Derivation Path</div>
                    <div class="field-value text-dim small" style="font-size:11px;color:var(--text-dim);">${w.path}</div>
                  </div>
                </div>`;

    div
      .querySelectorAll(".copy-btn[data-copy]")
      .forEach((btn) =>
        btn.addEventListener("click", () => copyText(btn.dataset.copy, btn)),
      );
    div
      .querySelectorAll(".copy-mnemonic-btn")
      .forEach((btn) =>
        btn.addEventListener("click", () =>
          copyText(btn.dataset.mnemonic, btn),
        ),
      );

    const addrQrBtn = createInlineQRButton(w.address, "Address QR", false);
    document.createElement("span");
    div.querySelector(`#qr-addr-slot-${index}`).appendChild(addrQrBtn);

    const wifQrBtn = createInlineQRButton(
      w.privateKeyWIF,
      "WIF Key Private",
      true,
    );
    div.querySelector(`#qr-wif-slot-${index}`).appendChild(wifQrBtn);

    const seedQrBtn = createInlineQRButton(
      w.mnemonic,
      "Seed Phrase | Private",
      true,
    );
    div.querySelector(`#qr-seed-slot-${index}`).appendChild(seedQrBtn);

    return div;
  }

  let generatedWallets = [];

  async function generate() {
    const btn = document.getElementById("generate-btn"),
      spinner = document.getElementById("gen-spinner");
    const btnText = document.getElementById("gen-btn-text"),
      area = document.getElementById("results-area");
    const actionRow = document.getElementById("action-row"),
      wipeBtn = document.getElementById("wipe-btn");
    const walletType = document.getElementById("wallet-type").value;
    const wordCount = parseInt(document.getElementById("word-count").value);
    const quantity = parseInt(document.getElementById("quantity").value);
    const passphrase = document.getElementById("passphrase").value;

    btn.disabled = true;
    spinner.classList.remove("hidden");
    btnText.textContent = "Generating";
    area.innerHTML = `<div class="loading-state"><div class="spinner"></div><div class="text-dim">Generating wallet<span class="loading-dots"></span></div></div>`;

    try {
      if (entropyMode === "dice" && !diceValid)
        throw new Error(
          "dice entropy not ready - enter at least 99 rolls (1-6)",
        );
      if (entropyMode === "string") {
        const str = document.getElementById("string-input").value;
        if (!str || str.length < 1)
          throw new Error("enter a string to derive wallet from");
        if (str.length < 20)
          throw new Error(
            "string too short - minimum 20 characters, 50+ strongly recommended",
          );
      }

      generatedWallets = [];
      const note = document.getElementById("entropy-mode-change-note");
      if (note) note.style.display = "none";

      for (let i = 0; i < quantity; i++) {
        let mnemonic;
        if (entropyMode === "dice") {
          mnemonic = await generateMnemonicWithDice(
            diceInput.value,
            wordCount,
            i,
            diceDeterministic,
          );
        } else if (entropyMode === "string") {
          const idxBuf = new Uint8Array(4);
          new DataView(idxBuf.buffer).setUint32(0, i, false);
          mnemonic = await generateMnemonicFromString(
            document.getElementById("string-input").value +
              "\x00" +
              String.fromCharCode(...idxBuf),
            wordCount,
          );
        } else {
          const extraBytes = new Uint8Array(mouseEntropySamples.length * 4);
          mouseEntropySamples.forEach((s, i) =>
            new DataView(extraBytes.buffer).setUint32(i * 4, s >>> 0, false),
          );
          mnemonic = await generateMnemonic(
            wordCount === 24 ? 256 : 128,
            extraBytes,
          );
        }
        const w = await generateWalletFromMnemonic(
          mnemonic,
          passphrase,
          walletType,
        );
        generatedWallets.push(w);
      }

      area.innerHTML = "";
      for (let i = 0; i < generatedWallets.length; i++)
        area.appendChild(renderWalletCard(generatedWallets[i], i));

      const validationResults = await Promise.all(
        generatedWallets.map((w) => validateRoundTrip(w)),
      );
      const failed = validationResults.filter((r) => !r.valid);
      if (failed.length > 0) {
        secureWipeAll(generatedWallets);
        generatedWallets = [];
        area.innerHTML = "";
        throw new Error(
          "CRITICAL: Round-trip validation failed!\n" +
            failed.flatMap((r) => r.errors).join("\n"),
        );
      }
      validationResults.forEach((r, i) => {
        const card = area.children[i];
        if (!card) return;
        const badge = document.createElement("div");
        badge.style.cssText =
          "font-size:11px;color:var(--green);font-family:var(--font-mono);margin-bottom:8px;letter-spacing:1px;";
        badge.textContent =
          "ROUND-TRIP VALIDATED - address re-derived from WIF key matches";
        card.insertBefore(badge, card.firstChild);
      });

      actionRow.classList.remove("hidden");
      wipeBtn.classList.remove("hidden");
      toast(
        `${quantity} wallet${quantity > 1 ? "s" : ""} generated & validated`,
        "success",
      );
      buildPrintArea();
    } catch (e) {
      console.error(e);
      area.innerHTML = `<div class="alert danger"><span class="alert-icon">✗</span><div class="alert-text"><strong>Generation failed</strong> ${e.message}</div></div>`;
      toast("generation failed: " + e.message, "error");
    }
    btn.disabled = false;
    spinner.classList.add("hidden");
    btnText.textContent = "⊕ Generate Wallet";
  }

  document.getElementById("generate-btn").addEventListener("click", generate);

  document.getElementById("wipe-btn").addEventListener("click", () => {
    secureWipeAll(generatedWallets);
    generatedWallets = [];
    document.getElementById("action-row").classList.add("hidden");
    document.getElementById("wipe-btn").classList.add("hidden");
    document.getElementById("results-area").innerHTML = "";
    toast("cleared from screen", "success");
    const note = document.getElementById("entropy-mode-change-note");
    if (note) note.style.display = "none";

    let warnBanner = document.getElementById("wipe-security-warning");
    if (!warnBanner) {
      warnBanner = document.createElement("div");
      warnBanner.id = "wipe-security-warning";
      warnBanner.style.cssText = `
      background: rgba(255, 51, 51, 0.15);
      border: 1px solid var(--red);
      border-radius: var(--radius);
      padding: 10px 14px;
      margin: 12px 0;
      font-size: 12px;
      font-family: var(--font-mono);
      color: var(--red);
      text-align: center;
    `;
      warnBanner.innerHTML = `
       <strong>Screen cleared.</strong> For full security: 
      <strong>close this tab and reboot</strong> before reconnecting to any network.
      JavaScript cannot guarantee memory zeroing.
    `;
      const resultsParent = document.getElementById("results-area").parentNode;
      resultsParent.insertBefore(
        warnBanner,
        document.getElementById("results-area"),
      );
    } else {
      warnBanner.style.display = "block";
    }
    setTimeout(() => {
      if (warnBanner) warnBanner.style.display = "none";
    }, 8000);
  });

  function buildPrintArea() {
    const area = document.getElementById("print-area");
    area.innerHTML =
      '<h2 style="font-size:18px;margin-bottom:16px;font-family:monospace">BITCOIN PAPER WALLETS - GENERATED OFFLINE</h2>';
    generatedWallets.forEach((w, i) => {
      const passphraseNote = w.passphrase
        ? `<div class="print-label" style="margin-top:10px;padding:6px 8px;border:1.5px solid #c8a000;border-radius:3px;color:#c8a000;font-weight:bold;">BIP39 PASSPHRASE (25TH WORD) WAS USED<br><span style="font-weight:normal;font-size:11px;">This wallet CANNOT be recovered from the seed phrase alone.</span></div>`
        : "";
      const addrCanvas = document.createElement("canvas");
      const wifCanvas = document.createElement("canvas");
      const seedCanvas = document.createElement("canvas");
      const d = document.createElement("div");
      d.className = "print-wallet";
      d.innerHTML = `
                  <div style="font-size:14px;font-weight:bold;margin-bottom:8px;font-family:monospace">WALLET #${i + 1} - ${w.typeName}</div>
                  <div class="print-section">
                    <div class="print-label">⬤ PUBLIC - Receiving Address (safe to share)</div>
                    <div class="print-value">${w.address}</div>
                    <div class="print-qr" data-pqr="addr"></div>
                  </div>
                  <div class="print-fold-line">▼ FOLD HERE - KEEP PRIVATE ▼</div>
                  <div class="print-section">
                    <div class="print-label">PRIVATE KEY WIF - NEVER SHARE</div>
                    <div class="print-value">${w.privateKeyWIF}</div>
                    <div class="print-qr" data-pqr="wif"></div>
                    <div class="print-label" style="margin-top:14px;">BIP39 SEED PHRASE (${w.mnemonic.split(" ").length} words) - NEVER SHARE</div>
                    <div class="print-value">${w.mnemonic}</div>
                    <div class="print-qr" data-pqr="seed"></div>
                    <div class="print-label" style="margin-top:8px;">DERIVATION PATH: ${w.path}</div>
                    ${passphraseNote}
                  </div>
                  <div class="print-warning">NEVER enter your private key or seed phrase on any website or device connected to the internet.</div>`;
      d.querySelector('[data-pqr="addr"]').appendChild(addrCanvas);
      d.querySelector('[data-pqr="wif"]').appendChild(wifCanvas);
      d.querySelector('[data-pqr="seed"]').appendChild(seedCanvas);
      area.appendChild(d);
      renderQR(w.address, addrCanvas, 120);
      renderQR(w.privateKeyWIF, wifCanvas, 120);
      renderQR(w.mnemonic, seedCanvas, 120);
    });
  }

  document
    .getElementById("print-btn")
    .addEventListener("click", () => window.print());
  document.getElementById("export-txt-btn").addEventListener("click", () => {
    if (!generatedWallets.length) return;
    const lines = [
      "BITCOIN PAPER WALLETS - GENERATED OFFLINE",
      "=".repeat(60),
      "",
    ];
    generatedWallets.forEach((w, i) => {
      lines.push(`WALLET #${i + 1} - ${w.typeName}`);
      lines.push(`Address:     ${w.address}`);
      lines.push(`WIF Key:     ${w.privateKeyWIF}`);
      lines.push(`Mnemonic:    ${w.mnemonic}`);
      lines.push(`Path:        ${w.path}`);
      if (w.passphrase)
        lines.push(
          `Passphrase:  A BIP39 PASSPHRASE WAS USED\n             Back up your passphrase separately - without it funds are LOST.`,
        );
      lines.push("");
      lines.push(
        "! SECURITY: Store private key in a secure physical location.",
      );
      lines.push("! Never enter your seed phrase on any online device.");
      lines.push("-".repeat(60));
      lines.push("");
    });
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `btc-wallets-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast("TXT exported - store securely!", "warn");
  });

  const importBtn = document.getElementById("import-btn");
  const mnemonicValidMsg = document.getElementById("mnemonic-valid-msg");
  let importWordCount = 12;

  function buildWordGrid(gridId, count) {
    const grid = document.getElementById(gridId);
    grid.innerHTML = "";
    for (let i = 1; i <= count; i++) {
      const wrap = document.createElement("div");
      wrap.className = "word-input-wrap";
      wrap.innerHTML = `<span class="word-input-num">${i}</span>
                  <input class="word-input-field" type="text" id="word-${gridId}-${i}"
                    placeholder="word" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">`;
      grid.appendChild(wrap);
    }
    grid.querySelectorAll(".word-input-field").forEach((inp, idx, all) => {
      inp.addEventListener("input", () => {
        inp.value = inp.value.toLowerCase().replace(/[^a-z]/g, "");
        validateImportWords();
      });
      inp.addEventListener("keydown", (e) => {
        if (e.key === " " || e.key === "Tab" || e.key === "Enter") {
          e.preventDefault();
          if (idx + 1 < all.length) all[idx + 1].focus();
        }
      });
      inp.addEventListener("paste", (e) => {
        e.preventDefault();
        const text = (e.clipboardData || window.clipboardData).getData("text");
        const words = text
          .trim()
          .toLowerCase()
          .split(/\s+/)
          .filter((w) => w.length > 0);
        if (words.length > 1) {
          words.forEach((word, wi) => {
            if (idx + wi < all.length)
              all[idx + wi].value = word.replace(/[^a-z]/g, "");
          });
          all[Math.min(idx + words.length, all.length - 1)].focus();
        } else inp.value = (words[0] || "").replace(/[^a-z]/g, "");
        validateImportWords();
      });
    });
  }

  function getImportMnemonic() {
    const gridId = importWordCount === 12 ? "word-grid-12" : "word-grid-24";
    return Array.from(
      document.getElementById(gridId).querySelectorAll(".word-input-field"),
    )
      .map((inp) => inp.value.trim())
      .filter((w) => w.length > 0)
      .join(" ");
  }

  let importValidTimeout;
  async function validateImportWords() {
    clearTimeout(importValidTimeout);
    importValidTimeout = setTimeout(async () => {
      const mnemonic = getImportMnemonic();
      const words = mnemonic.split(" ").filter((w) => w);
      const gridId = importWordCount === 12 ? "word-grid-12" : "word-grid-24";
      const allInputs = document
        .getElementById(gridId)
        .querySelectorAll(".word-input-field");
      if (words.length < importWordCount) {
        mnemonicValidMsg.classList.add("hidden");
        importBtn.disabled = true;
        allInputs.forEach(
          (inp) =>
            (inp.closest(".word-input-wrap").className = "word-input-wrap"),
        );
        return;
      }
      const valid = await validateMnemonic(mnemonic);
      mnemonicValidMsg.classList.remove("hidden");
      if (valid) {
        mnemonicValidMsg.className = "validation-msg valid";
        mnemonicValidMsg.innerHTML =
          "✓ Valid BIP39 mnemonic - checksum correct";
        importBtn.disabled = false;
        allInputs.forEach(
          (inp) =>
            (inp.closest(".word-input-wrap").className =
              "word-input-wrap valid"),
        );
      } else {
        mnemonicValidMsg.className = "validation-msg invalid";
        mnemonicValidMsg.innerHTML =
          "Invalid mnemonic - check spelling or word order";
        importBtn.disabled = true;
        allInputs.forEach(
          (inp) =>
            (inp.closest(".word-input-wrap").className =
              "word-input-wrap invalid"),
        );
      }
    }, 400);
  }

  document
    .getElementById("import-word-count-toggle")
    .addEventListener("click", () => {
      importWordCount = importWordCount === 12 ? 24 : 12;
      document.getElementById("import-word-count-toggle").textContent =
        importWordCount === 12 ? "12 WORDS" : "24 WORDS";
      document
        .getElementById("word-grid-12")
        .classList.toggle("hidden", importWordCount !== 12);
      document
        .getElementById("word-grid-24")
        .classList.toggle("hidden", importWordCount !== 24);
      mnemonicValidMsg.classList.add("hidden");
      importBtn.disabled = true;
    });

  document
    .getElementById("import-paste-btn")
    .addEventListener("click", async () => {
      try {
        let text;
        if (navigator.clipboard && navigator.clipboard.readText)
          text = await navigator.clipboard.readText();
        else {
          toast("clipboard access denied, type words manually", "warn");
          return;
        }
        const words = text
          .trim()
          .toLowerCase()
          .split(/\s+/)
          .filter((w) => w.length > 0);
        const count = words.length === 24 ? 24 : 12;
        if (count !== importWordCount) {
          importWordCount = count;
          document.getElementById("import-word-count-toggle").textContent =
            count + " WORDS";
          document
            .getElementById("word-grid-12")
            .classList.toggle("hidden", count !== 12);
          document
            .getElementById("word-grid-24")
            .classList.toggle("hidden", count !== 24);
        }
        const inputs = document
          .getElementById(count === 12 ? "word-grid-12" : "word-grid-24")
          .querySelectorAll(".word-input-field");
        inputs.forEach((inp, i) => {
          inp.value = (words[i] || "").replace(/[^a-z]/g, "");
        });
        validateImportWords();
        toast("mnemonic pasted", "success");
      } catch (e) {
        toast("clipboard access denied - type words manually", "warn");
      }
    });

  buildWordGrid("word-grid-12", 12);
  buildWordGrid("word-grid-24", 24);

  let deriveMode = "single";
  document
    .getElementById("derive-mode-single")
    .addEventListener("click", () => {
      deriveMode = "single";
      document.getElementById("derive-mode-single").style.background =
        "rgba(0,255,65,0.1)";
      document.getElementById("derive-mode-single").style.color =
        "var(--green)";
      document.getElementById("derive-mode-range").style.background =
        "transparent";
      document.getElementById("derive-mode-range").style.color =
        "var(--text-dim)";
      document.getElementById("derive-single-opts").classList.remove("hidden");
      document.getElementById("derive-range-opts").classList.add("hidden");
      document.getElementById("import-btn").textContent = "↓ Derive Wallet";
    });
  document.getElementById("derive-mode-range").addEventListener("click", () => {
    deriveMode = "range";
    document.getElementById("derive-mode-range").style.background =
      "rgba(0,255,65,0.1)";
    document.getElementById("derive-mode-range").style.color = "var(--green)";
    document.getElementById("derive-mode-single").style.background =
      "transparent";
    document.getElementById("derive-mode-single").style.color =
      "var(--text-dim)";
    document.getElementById("derive-range-opts").classList.remove("hidden");
    document.getElementById("derive-single-opts").classList.add("hidden");
    document.getElementById("import-btn").textContent = "⋮ Derive Addresses";
  });

  importBtn.addEventListener("click", async () => {
    const mnemonic = getImportMnemonic();
    const resultsDiv = document.getElementById("import-results");
    importBtn.disabled = true;

    if (deriveMode === "single") {
      const walletType = document.getElementById("import-wallet-type").value;
      const passphrase = document.getElementById("import-passphrase").value;
      const addrIndex =
        parseInt(document.getElementById("import-addr-index").value) || 0;
      resultsDiv.innerHTML = `<div class="loading-state"><div class="spinner"></div><div class="text-dim">Deriving wallet<span class="loading-dots"></span></div></div>`;
      try {
        const w = await generateWalletFromMnemonic(
          mnemonic,
          passphrase,
          walletType,
          0,
          addrIndex,
        );
        const vr = await validateRoundTrip(w);
        if (!vr.valid)
          throw new Error(
            "round-trip validation failed: " + vr.errors.join(", "),
          );
        resultsDiv.innerHTML = "";
        resultsDiv.appendChild(renderWalletCard(w, 0));
        toast("wallet derived", "success");
      } catch (e) {
        resultsDiv.innerHTML = `<div class="alert danger"><span class="alert-icon">✗</span><div class="alert-text"><strong>error</strong> ${e.message}</div></div>`;
      }
    } else {
      const walletType = document.getElementById("hd-wallet-type").value;
      const passphrase = document.getElementById("hd-passphrase").value;
      const count = parseInt(document.getElementById("hd-count").value);
      const branch = parseInt(document.getElementById("hd-branch").value);
      const accountIndex = parseInt(
        document.getElementById("hd-account").value,
      );
      const customPath = document.getElementById("hd-custom-path").value.trim();
      try {
        const startIndexRaw = document
          .getElementById("hd-start-index")
          .value.trim();
        const startIndex =
          startIndexRaw === "" ? 0 : parseInt(startIndexRaw, 10);
        if (
          isNaN(startIndex) ||
          !Number.isInteger(startIndex) ||
          startIndex < 0 ||
          startIndex > 2147483647
        ) {
          resultsDiv.innerHTML = `<div class="alert danger"><span class="alert-icon">✗</span><div class="alert-text"><strong>Invalid start index</strong> - must be 0-2,147,483,647</div></div>`;
          importBtn.disabled = false;
          return;
        }
        resultsDiv.innerHTML = `<div class="loading-state"><div class="spinner"></div><div class="text-dim">Deriving ${count} addresses<span class="loading-dots"></span></div></div>`;
        const addresses = await deriveMultipleAddresses(
          mnemonic,
          passphrase,
          walletType,
          count,
          branch,
          accountIndex,
          customPath || null,
          startIndex,
        );

        const validatedAddresses = [];
        for (const a of addresses) {
          const mockWallet = {
            privateKeyWIF: a.privateKeyWIF,
            walletType: walletType,
            address: a.address,
          };
          const vr = await validateRoundTrip(mockWallet);
          if (!vr.valid) {
            throw new Error(
              `Round‑trip validation failed for address index ${a.index}: ${vr.errors.join(", ")}`,
            );
          }
          validatedAddresses.push(a);
        }

        resultsDiv.innerHTML = `
                    <div class="section">
                      <div class="section-header"><span class="dot"></span>Derived Addresses - ${walletType.replace("_", " ")} · ${count} addresses</div>
                      <div class="section-body" style="padding:0;overflow-x:auto;">
                        <table class="addr-table">
                          <thead><tr><th>#</th><th>Path</th><th>Address</th><th>WIF Private Key</th></tr></thead>
                          <tbody>
                            ${addresses
                              .map(
                                (a) => `
                              <tr>
                                <td class="td-index">${a.index}</td>
                                <td class="td-path">${a.path}</td>
                                <td class="td-addr" style="position:relative;">
                                  <span style="word-break:break-all;">${a.address}</span>
                                  <div style="display:flex;gap:4px;margin-top:4px;flex-wrap:wrap;">
                                    <button class="copy-btn" data-copy="${a.address}">copy</button>
                                    <span class="row-qr-slot-addr"></span>
                                  </div>
                                </td>
                                <td class="td-wif" style="position:relative;">
                                  <span style="word-break:break-all;color:var(--yellow);">${a.privateKeyWIF}</span>
                                  <div style="display:flex;gap:4px;margin-top:4px;flex-wrap:wrap;">
                                    <button class="copy-btn" data-copy="${a.privateKeyWIF}">copy</button>
                                    <span class="row-qr-slot-wif"></span>
                                  </div>
                                </td>
                              </tr>`,
                              )
                              .join("")}
                          </tbody>
                        </table>
                      </div>
                    </div>`;

        resultsDiv
          .querySelectorAll(".copy-btn[data-copy]")
          .forEach((btn) =>
            btn.addEventListener("click", () =>
              copyText(btn.dataset.copy, btn),
            ),
          );

        const rows = resultsDiv.querySelectorAll("tbody tr");
        rows.forEach((row, i) => {
          const a = addresses[i];
          const addrSlot = row.querySelector(".row-qr-slot-addr");
          const wifSlot = row.querySelector(".row-qr-slot-wif");
          const addrBtn = createInlineQRButton(a.address, "Address QR", false);
          addrSlot.appendChild(addrBtn);
          const wifBtn = createInlineQRButton(
            a.privateKeyWIF,
            "WIF Key Private",
            true,
          );
          wifSlot.appendChild(wifBtn);
        });

        toast(`${count} addresses derived`, "success");
      } catch (e) {
        resultsDiv.innerHTML = `<div class="alert danger"><span class="alert-icon">✗</span><div class="alert-text"><strong>error</strong> ${e.message}</div></div>`;
      }
    }
    importBtn.disabled = false;
  });

  document
    .getElementById("verify-mnemonic")
    .addEventListener("input", async (e) => {
      const val = e.target.value.trim(),
        result = document.getElementById("verify-result");
      if (!val) {
        result.innerHTML = "";
        return;
      }
      const words = val.split(/\s+/);
      if (words.length < 12) {
        result.innerHTML = `<div class="text-dim small">Enter at least 12 words (${words.length}/12+)</div>`;
        return;
      }
      const valid = await validateMnemonic(val);
      if (valid)
        result.innerHTML = `<div class="alert success"><div class="alert-text"><strong>Valid BIP39 mnemonic</strong> - ${words.length} words, checksum correct.</div></div>`;
      else
        result.innerHTML = `<div class="alert danger"><span class="alert-icon">✗</span><div class="alert-text"><strong>Invalid mnemonic</strong> - checksum failed. Possible causes: typo, wrong word order, or not a valid BIP39 phrase.</div></div>`;
    });

  function updatePathPreview() {
    const walletType = document.getElementById("hd-wallet-type").value;
    const branch = document.getElementById("hd-branch").value;
    const account = document.getElementById("hd-account").value;
    const custom = document.getElementById("hd-custom-path").value.trim();
    const preview = document.getElementById("hd-custom-path-preview");
    const mismatchEl = document.getElementById("hd-path-mismatch-warn");
    const purpose =
      walletType === "LEGACY"
        ? "44'"
        : walletType === "SEGWIT"
          ? "49'"
          : walletType === "TAPROOT"
            ? "86'"
            : "84'";
    if (custom) {
      const base = custom.replace(/\/\d+$/, "");
      preview.textContent = `-> Will derive: ${base}/0, ${base}/1, ${base}/2…`;
      preview.style.color = "var(--yellow)";
      const PURPOSE_MAP = {
        44: { type: "LEGACY", label: "Legacy (P2PKH)", btn: "LEGACY" },
        49: { type: "SEGWIT", label: "SegWit P2SH", btn: "SEGWIT" },
        84: {
          type: "NATIVE_SEGWIT",
          label: "Native SegWit",
          btn: "NATIVE_SEGWIT",
        },
        86: { type: "TAPROOT", label: "Taproot (P2TR)", btn: "TAPROOT" },
      };
      const TYPE_NAMES = {
        LEGACY: "Legacy (P2PKH)",
        SEGWIT: "SegWit P2SH",
        NATIVE_SEGWIT: "Native SegWit",
        TAPROOT: "Taproot (P2TR)",
      };
      const purposeMatch = custom.match(/^m\/(\d+)'?\//);
      const knownPurpose = purposeMatch ? PURPOSE_MAP[purposeMatch[1]] : null;
      if (knownPurpose && knownPurpose.type !== walletType) {
        mismatchEl.innerHTML = `Path <strong>m/${purposeMatch[1]}'…</strong> is conventionally <strong>${knownPurpose.label}</strong> - you have <strong>${TYPE_NAMES[walletType]}</strong> selected. <span id="mismatch-fix-btn" style="cursor:pointer;text-decoration:underline;color:var(--green);">[Switch to ${knownPurpose.label}]</span>`;
        mismatchEl.style.display = "block";
        requestAnimationFrame(() => {
          const fixBtn = document.getElementById("mismatch-fix-btn");
          if (fixBtn)
            fixBtn.addEventListener("click", () => {
              document.getElementById("hd-wallet-type").value =
                knownPurpose.btn;
              updatePathPreview();
            });
        });
      } else {
        mismatchEl.style.display = "none";
        mismatchEl.innerHTML = "";
      }
    } else {
      preview.textContent = `-> Will derive: m/${purpose}/0'/${account}'/${branch}/0, …/1, …/2…`;
      preview.style.color = "var(--text-muted)";
      mismatchEl.style.display = "none";
      mismatchEl.innerHTML = "";
    }
  }
  ["hd-wallet-type", "hd-branch", "hd-account"].forEach((id) =>
    document.getElementById(id).addEventListener("change", updatePathPreview),
  );
  document
    .getElementById("hd-custom-path")
    .addEventListener("input", updatePathPreview);
  updatePathPreview();

  const PALETTE = [
    "#00ff41",
    "#00d4aa",
    "#f7931a",
    "#7c3aed",
    "#e8d44d",
    "#ff6b6b",
    "#4ecdc4",
    "#45b7d1",
    "#96ceb4",
    "#ffeaa7",
    "#dda0dd",
    "#98d8c8",
  ];

  function renderWordChips(matches) {
    const div = document.getElementById("wl-results");
    if (!matches.length) {
      div.innerHTML = `<div class="text-dim small">No matches.</div>`;
      return;
    }
    div.innerHTML = `<div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;font-family:var(--font-mono);">${matches.length} result${matches.length !== 1 ? "s" : ""}</div>
                <div style="display:flex;flex-wrap:wrap;gap:6px;">
                  ${matches
                    .map(({ word, index }) => {
                      const bin = index.toString(2).padStart(11, "0");
                      return `<div style="display:flex;align-items:center;gap:6px;background:var(--bg2);border:1px solid var(--border2);border-radius:var(--radius);padding:5px 10px;cursor:default;" title="BIP39 word #${index + 1} = ${bin}">
                      <span style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono);min-width:30px;text-align:right;">#${index + 1}</span>
                      <span style="font-family:var(--font-mono);color:var(--green);font-size:13px;font-weight:600;">${word}</span>
                      <span style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono);">${bin}</span>
                    </div>`;
                    })
                    .join("")}
                </div>`;
  }
  document.getElementById("wl-prefix").addEventListener("input", (e) => {
    document.getElementById("wl-index").value = "";
    const q = e.target.value.trim().toLowerCase();
    if (!q) {
      document.getElementById("wl-results").innerHTML = "";
      return;
    }
    renderWordChips(
      WORDLIST.map((word, index) => ({ word, index })).filter(({ word }) =>
        word.startsWith(q),
      ),
    );
  });
  document.getElementById("wl-index").addEventListener("input", (e) => {
    document.getElementById("wl-prefix").value = "";
    const val = e.target.value.trim();
    if (val === "") {
      document.getElementById("wl-results").innerHTML = "";
      return;
    }
    const idx = parseInt(val) - 1;
    if (isNaN(idx) || idx < 0 || idx > 2047) {
      document.getElementById("wl-results").innerHTML =
        `<div class="text-dim small" style="color:var(--red);">Index must be 1-2048</div>`;
      return;
    }
    renderWordChips([{ word: WORDLIST[idx], index: idx }]);
  });

  function setInspTab(mode) {
    const isHex = mode === "hex";
    document.getElementById("insp-tab-hex").style.background = isHex
      ? "rgba(0,255,65,0.1)"
      : "transparent";
    document.getElementById("insp-tab-hex").style.color = isHex
      ? "var(--green)"
      : "var(--text-dim)";
    document.getElementById("insp-tab-words").style.background = !isHex
      ? "rgba(0,255,65,0.1)"
      : "transparent";
    document.getElementById("insp-tab-words").style.color = !isHex
      ? "var(--green)"
      : "var(--text-dim)";
    document
      .getElementById("insp-panel-hex")
      .classList.toggle("hidden", !isHex);
    document
      .getElementById("insp-panel-words")
      .classList.toggle("hidden", isHex);
  }
  document
    .getElementById("insp-tab-hex")
    .addEventListener("click", () => setInspTab("hex"));
  document
    .getElementById("insp-tab-words")
    .addEventListener("click", () => setInspTab("words"));

  function colouredBits(bits) {
    let html = `<div style="font-family:var(--font-mono);font-size:11px;line-height:2;word-break:break-all;">`;
    for (let i = 0; i < bits.length; i += 11) {
      const chunk = bits.slice(i, i + 11);
      const col = PALETTE[Math.floor(i / 11) % PALETTE.length];
      html += `<span style="color:${col};">${chunk}</span>`;
    }
    return html + "</div>";
  }
  function iRow(label, content) {
    return `<div style="margin-bottom:14px;"><div style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono);letter-spacing:1px;text-transform:uppercase;margin-bottom:4px;">${label}</div>${content}</div>`;
  }

  async function runHexInspect() {
    const raw = document
      .getElementById("insp-hex")
      .value.trim()
      .replace(/\s/g, "")
      .toLowerCase();
    const out = document.getElementById("insp-hex-out");
    if (!raw) {
      out.innerHTML = "";
      return;
    }
    if (!/^[0-9a-f]+$/.test(raw)) {
      out.innerHTML = `<div class="alert danger"><span class="alert-icon">✗</span><div class="alert-text">Invalid hex - only 0-9 and a-f</div></div>`;
      return;
    }
    if (raw.length !== 32 && raw.length !== 64) {
      out.innerHTML = `<div class="alert danger"><span class="alert-icon">✗</span><div class="alert-text">Need 32 hex chars (128-bit / 12 words) or 64 hex chars (256-bit / 24 words). Got ${raw.length}.</div></div>`;
      return;
    }
    const entBytes = hexToBytes(raw);
    const csFull = await sha256(entBytes);
    const entBits = Array.from(entBytes)
      .map((b) => b.toString(2).padStart(8, "0"))
      .join("");
    const csLen = entBytes.length / 4;
    const csBits = csFull[0].toString(2).padStart(8, "0").slice(0, csLen);
    const allBits = entBits + csBits;
    const wordCount = allBits.length / 11;
    const indices = [];
    for (let i = 0; i < allBits.length; i += 11)
      indices.push(parseInt(allBits.slice(i, i + 11), 2));
    const words = indices.map((i) => WORDLIST[i]);
    let html = `<div style="background:var(--bg2);border:1px solid var(--border2);border-radius:var(--radius);padding:16px;">`;
    html += iRow(
      `Step 1 - Entropy (${entBytes.length} bytes = ${entBytes.length * 8} bits)`,
      `<div style="font-family:var(--font-mono);font-size:12px;color:var(--green);word-break:break-all;">${raw.toUpperCase()}</div>`,
    );
    html += iRow(
      `Step 2 - Entropy bits (${entBits.length} bits) coloured in 11-bit groups`,
      colouredBits(entBits),
    );
    html += iRow(
      `Step 3 - SHA-256(entropy) - first ${csLen} bits used as checksum`,
      `<div style="font-family:var(--font-mono);font-size:11px;line-height:1.8;"><span style="color:var(--text-muted);">Full hash:  </span><span style="color:var(--text-dim);">${bytesToHex(csFull).toUpperCase()}</span><br><span style="color:var(--text-muted);">Used bits:  </span><span style="color:var(--yellow);">${csBits}</span></div>`,
    );
    html += iRow(
      `Step 4 - All bits = entropy ‖ checksum (${allBits.length} bits = ${wordCount} × 11)`,
      colouredBits(allBits),
    );
    html += iRow(
      `Step 5 - 11-bit chunks -> index -> BIP39 word`,
      `<div style="overflow-x:auto;"><table style="border-collapse:collapse;width:100%;"><thead><tr><th style="padding:4px 8px;font-family:var(--font-mono);font-size:10px;color:var(--text-muted);text-align:left;border-bottom:1px solid var(--border);">#</th><th style="padding:4px 8px;font-family:var(--font-mono);font-size:10px;color:var(--text-muted);text-align:left;border-bottom:1px solid var(--border);">11 bits</th><th style="padding:4px 8px;font-family:var(--font-mono);font-size:10px;color:var(--text-muted);text-align:left;border-bottom:1px solid var(--border);">decimal (word #)</th><th style="padding:4px 8px;font-family:var(--font-mono);font-size:10px;color:var(--text-muted);text-align:left;border-bottom:1px solid var(--border);">word</th></tr></thead><tbody>${indices
        .map((idx, i) => {
          const chunk = allBits.slice(i * 11, (i + 1) * 11);
          const col = PALETTE[i % PALETTE.length];
          return `<tr><td style="padding:3px 8px;font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">${i + 1}</td><td style="padding:3px 8px;font-family:var(--font-mono);font-size:11px;color:${col};">${chunk}</td><td style="padding:3px 8px;font-family:var(--font-mono);font-size:11px;color:var(--text-dim);">${idx} <span style="color:var(--text-muted);">-> (#${idx + 1})</span></td><td style="padding:3px 8px;font-family:var(--font-mono);font-size:13px;color:${col};font-weight:600;">${WORDLIST[idx]}</td></tr>`;
        })
        .join("")}</tbody></table></div>`,
    );
    html += iRow(
      `Result - ${wordCount}-word BIP39 mnemonic`,
      `<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;"><button class="copy-btn insp-copy-all" data-copy="${words.join(" ")}" style="font-size:11px;padding:4px 12px;">⎘ copy all ${wordCount} words</button></div><div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px;">${words.map((w, i) => `<span style="background:var(--bg3);border:1px solid var(--border2);border-radius:var(--radius);padding:4px 10px;font-family:var(--font-mono);font-size:13px;color:${PALETTE[i % PALETTE.length]};font-weight:600;display:flex;align-items:center;gap:6px;cursor:pointer;" class="insp-word-chip" data-copy="${w}"><span style="color:var(--text-muted);font-size:10px;">${i + 1}</span>${w}</span>`).join("")}</div>`,
    );
    html += "</div>";
    out.innerHTML = html;
    out
      .querySelectorAll(".insp-copy-all,.insp-word-chip")
      .forEach((el) =>
        el.addEventListener("click", () => copyText(el.dataset.copy, el)),
      );
  }
  document
    .getElementById("insp-hex-run")
    .addEventListener("click", runHexInspect);
  document.getElementById("insp-hex").addEventListener("keydown", (e) => {
    if (e.key === "Enter") runHexInspect();
  });
  document.getElementById("insp-hex-rand").addEventListener("click", () => {
    document.getElementById("insp-hex").value = bytesToHex(
      crypto.getRandomValues(new Uint8Array(16)),
    );
    runHexInspect();
  });

  async function runWordsInspect() {
    const raw = document
      .getElementById("insp-words")
      .value.trim()
      .toLowerCase();
    const out = document.getElementById("insp-words-out");
    if (!raw) {
      out.innerHTML = "";
      return;
    }
    const words = raw.split(/\s+/).filter((w) => w);
    if (words.length !== 12 && words.length !== 24) {
      out.innerHTML = `<div class="alert danger"><span class="alert-icon">✗</span><div class="alert-text">Need exactly 12 or 24 words. Got ${words.length}.</div></div>`;
      return;
    }
    const unknown = words.filter((w) => !WORDLIST.includes(w));
    if (unknown.length) {
      out.innerHTML = `<div class="alert danger"><span class="alert-icon">✗</span><div class="alert-text">Unknown words: <strong>${unknown.join(", ")}</strong> - check spelling.</div></div>`;
      return;
    }
    const allBits = words
      .map((w) => WORDLIST.indexOf(w).toString(2).padStart(11, "0"))
      .join("");
    const entBitLen = Math.floor(allBits.length / 33) * 32;
    const entBits = allBits.slice(0, entBitLen),
      storedCS = allBits.slice(entBitLen);
    const entBytes = new Uint8Array(
      entBits.match(/.{8}/g).map((b) => parseInt(b, 2)),
    );
    const entHex = bytesToHex(entBytes);
    const csFull = await sha256(entBytes);
    const csLen = entBytes.length / 4;
    const computedCS = csFull[0].toString(2).padStart(8, "0").slice(0, csLen);
    const valid = computedCS === storedCS;
    let html = `<div style="background:var(--bg2);border:1px solid var(--border${valid ? "2" : ""});${valid ? "" : "border-color:var(--red);"}border-radius:var(--radius);padding:16px;">`;
    html += iRow(
      "Step 1 - Word indices",
      `<div style="display:flex;flex-wrap:wrap;gap:4px;">${words
        .map((w, i) => {
          const idx = WORDLIST.indexOf(w);
          const col = PALETTE[i % PALETTE.length];
          return `<span style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:3px 8px;font-family:var(--font-mono);font-size:11px;"><span style="color:var(--text-muted);">${i + 1} </span><span style="color:${col};font-weight:600;">${w}</span><span style="color:var(--text-muted);"> #${idx + 1}</span></span>`;
        })
        .join("")}</div>`,
    );
    html += iRow(
      "Step 2 - All bits (11 bits per word, coloured by word)",
      colouredBits(allBits),
    );
    html += iRow(
      `Step 3 - Split: ${entBitLen} entropy bits + ${storedCS.length} checksum bits`,
      `<div style="font-family:var(--font-mono);font-size:11px;line-height:2;word-break:break-all;"><span style="color:var(--green);">${entBits}</span><span style="color:var(--yellow);border:1px solid var(--yellow);border-radius:2px;padding:0 3px;margin-left:4px;">${storedCS}</span></div>`,
    );
    html += iRow(
      "Step 4 - Entropy as hex",
      `<div style="font-family:var(--font-mono);font-size:12px;color:var(--green);word-break:break-all;">${entHex.toUpperCase()}</div>`,
    );
    html += iRow(
      "Step 5 - Checksum verification",
      `<div style="font-family:var(--font-mono);font-size:11px;line-height:2;"><div>Stored checksum:   <span style="color:var(--yellow);">${storedCS}</span></div><div>SHA-256 computed:  <span style="color:var(--yellow);">${computedCS}</span></div><div style="margin-top:4px;font-size:13px;color:${valid ? "var(--green)" : "var(--red)"};">${valid ? "✓ VALID - checksums match" : "✗ INVALID - checksums differ (word typo or wrong order)"}</div></div>`,
    );
    html += "</div>";
    out.innerHTML = html;
  }
  document
    .getElementById("insp-words-run")
    .addEventListener("click", runWordsInspect);

  function setKcTab(mode) {
    ["hex", "wif", "addr"].forEach((m) => {
      const on = m === mode;
      document.getElementById(`kc-tab-${m}`).style.background = on
        ? "rgba(0,255,65,0.1)"
        : "transparent";
      document.getElementById(`kc-tab-${m}`).style.color = on
        ? "var(--green)"
        : "var(--text-dim)";
      document.getElementById(`kc-panel-${m}`).classList.toggle("hidden", !on);
    });
  }
  document
    .getElementById("kc-tab-hex")
    .addEventListener("click", () => setKcTab("hex"));
  document
    .getElementById("kc-tab-wif")
    .addEventListener("click", () => setKcTab("wif"));
  document
    .getElementById("kc-tab-addr")
    .addEventListener("click", () => setKcTab("addr"));

  function kcRow(label, value, col = "var(--green)") {
    const safe = value.replace(/</g, "&lt;");
    return `<div style="margin-bottom:10px;">
                <div style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono);letter-spacing:1px;text-transform:uppercase;margin-bottom:3px;">${label}</div>
                <div style="display:flex;align-items:flex-start;gap:8px;flex-wrap:wrap;">
                  <span style="font-family:var(--font-mono);font-size:12px;color:${col};word-break:break-all;flex:1;">${safe}</span>
                  <button class="copy-btn" data-copy="${value}" style="flex-shrink:0;">copy</button>
                </div>
              </div>`;
  }

  document.getElementById("kc-hex-run").addEventListener("click", async () => {
    const raw = document
      .getElementById("kc-hex-in")
      .value.trim()
      .replace(/\s/g, "");
    const out = document.getElementById("kc-hex-out");
    if (!raw) {
      out.innerHTML = "";
      return;
    }
    if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
      out.innerHTML = `<div class="alert danger"><span class="alert-icon">✗</span><div class="alert-text">need exactly 64 hex characters (32 bytes), Got ${raw.length}</div></div>`;
      return;
    }
    try {
      const N_MAX =
        0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
      const privBI = bytesToBigInt(hexToBytes(raw));
      if (privBI === 0n || privBI >= N_MAX) {
        out.innerHTML = `<div class="alert danger"><span class="alert-icon">✗</span><div class="alert-text">key is outside valid secp256k1 range (1 to N-1)</div></div>`;
        return;
      }
      const wifC = await privateKeyToWIF(privBI, true);
      const wifU = await privateKeyToWIF(privBI, false);
      const pubC = privateKeyToPublicKey(privBI, true);
      const pubU = privateKeyToPublicKey(privBI, false);
      const addrNsw = await pubKeyToNativeSegwit(pubC);
      const addrSw = await pubKeyToSegwit(pubC);
      const addrLgC = await pubKeyToLegacy(pubC);
      const addrLgU = await pubKeyToLegacy(pubU);
      const addrTaproot = await pubKeyToTaproot(pubC);

      out.innerHTML = `<div style="background:var(--bg2);border:1px solid var(--border2);border-radius:var(--radius);padding:16px;">
                  ${kcRow("WIF - compressed (most wallets use this)", wifC, "var(--green)")}
                  ${kcRow("WIF - uncompressed (legacy only)", wifU, "var(--text-dim)")}
                  ${kcRow("Public key - compressed 33 bytes", bytesToHex(pubC).toUpperCase(), "var(--green-dim)")}
                  ${kcRow("Public key - uncompressed 65 bytes", bytesToHex(pubU).toUpperCase(), "var(--text-muted)")}
                  <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border);">
                    <div style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono);letter-spacing:1px;text-transform:uppercase;margin-bottom:10px;">Derived addresses (from compressed pubkey)</div>
                    ${kcRow("Native SegWit  bc1q...  (lowest fees, modern)", addrNsw, "var(--green)")}
                    ${kcRow("SegWit P2SH    3...     (compatible)", addrSw, "var(--green-dim)")}
                    ${kcRow("Legacy         1...     (compressed pubkey)", addrLgC, "var(--text-dim)")}
                    ${kcRow("Legacy         1...     (uncompressed pubkey)", addrLgU, "var(--text-muted)")}
                    ${kcRow("Taproot      bc1p...   (modern, lowest fees)", addrTaproot, "var(--orange)")}
                  </div>
                </div>`;
      out
        .querySelectorAll(".copy-btn")
        .forEach((btn) =>
          btn.addEventListener("click", () => copyText(btn.dataset.copy, btn)),
        );
    } catch (e) {
      out.innerHTML = `<div class="alert danger"><span class="alert-icon">✗</span><div class="alert-text">${e.message}</div></div>`;
    }
  });

  document.getElementById("kc-wif-run").addEventListener("click", async () => {
    const wif = document.getElementById("kc-wif-in").value.trim();
    const out = document.getElementById("kc-wif-out");
    if (!wif) {
      out.innerHTML = "";
      return;
    }
    try {
      const decoded = base58Decode(wif);
      if (decoded.length !== 37 && decoded.length !== 38)
        throw new Error(
          `WIF decoded to unexpected length: ${decoded.length} bytes`,
        );
      if (decoded[0] !== 0x80)
        throw new Error(
          "not a Bitcoin mainnet WIF key (expected version byte 0x80)",
        );
      const payload = decoded.slice(0, decoded.length - 4);
      const storedCS = decoded.slice(-4);
      const computedCS = (await sha256d(payload)).slice(0, 4);
      for (let i = 0; i < 4; i++)
        if (storedCS[i] !== computedCS[i])
          throw new Error(
            "WIF checksum invalid - key may be corrupted or mistyped",
          );
      const keyBytes = decoded.slice(1, 33);
      const privBI = bytesToBigInt(keyBytes);
      const pubC = privateKeyToPublicKey(privBI, true);
      const hexKey = bytesToHex(keyBytes).toUpperCase();
      const addrNsw = await pubKeyToNativeSegwit(pubC);
      const addrSw = await pubKeyToSegwit(pubC);
      const addrLg = await pubKeyToLegacy(pubC);
      const addrTaproot = await pubKeyToTaproot(pubC);

      out.innerHTML = `<div style="background:var(--bg2);border:1px solid var(--border2);border-radius:var(--radius);padding:16px;">
                  ${kcRow("Private key hex", hexKey, "var(--green)")}
                  ${kcRow("Public key (compressed)", bytesToHex(pubC).toUpperCase(), "var(--green-dim)")}
                  <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border);">
                    <div style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono);letter-spacing:1px;text-transform:uppercase;margin-bottom:10px;">Addresses</div>
                    ${kcRow("Native SegWit  bc1q...", addrNsw, "var(--green)")}
                    ${kcRow("SegWit P2SH    3...", addrSw, "var(--green-dim)")}
                    ${kcRow("Legacy         1...", addrLg, "var(--text-dim)")}
                    ${kcRow("Taproot      bc1p...", addrTaproot, "var(--orange)")}
                  </div>
                </div>`;
      out
        .querySelectorAll(".copy-btn")
        .forEach((btn) =>
          btn.addEventListener("click", () => copyText(btn.dataset.copy, btn)),
        );
    } catch (e) {
      out.innerHTML = `<div class="alert danger"><span class="alert-icon">✗</span><div class="alert-text">${e.message}</div></div>`;
    }
  });

  document.getElementById("kc-addr-in").addEventListener("input", async (e) => {
    const addr = e.target.value.trim();
    const out = document.getElementById("kc-addr-out");
    if (!addr) {
      out.innerHTML = "";
      return;
    }
    const result = await validateBitcoinAddress(addr);
    if (result.valid) {
      out.innerHTML = `<div class="alert success">
      <div class="alert-text">
        <strong>Valid Bitcoin address - ${result.type}</strong><br>
        <span style="font-family:var(--font-mono);font-size:11px;word-break:break-all;">${addr}</span><br>
        <span style="font-size:11px;color:var(--text-dim);">${result.note}</span>
      </div>
    </div>`;
    } else {
      out.innerHTML = `<div class="alert danger">
      <span class="alert-icon">✗</span>
      <div class="alert-text">
        <strong>Invalid address</strong><br>
        <span style="font-size:11px;">${result.reason}</span>
      </div>
    </div>`;
    }
  });

  const SECP256K1_N =
    0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

  let pkvBits = new Array(256).fill(false);

  function pkvBitsToHex() {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 256; i++) {
      if (pkvBits[i]) bytes[Math.floor(i / 8)] |= 1 << (7 - (i % 8));
    }
    return bytesToHex(bytes);
  }

  function pkvHexToBits(hex) {
    const bytes = hexToBytes(hex.padStart(64, "0").slice(0, 64));
    for (let i = 0; i < 256; i++) {
      pkvBits[i] = !!((bytes[Math.floor(i / 8)] >> (7 - (i % 8))) & 1);
    }
  }

  function pkvRender() {
    const hex = pkvBitsToHex();
    const bigint = bytesToBigInt(hexToBytes(hex));
    const binaryStr = pkvBits.map((b) => (b ? "1" : "0")).join("");

    const cells = document.getElementById("pkv-grid").children;
    for (let i = 0; i < 256; i++) {
      const cell = cells[i];
      const isOne = pkvBits[i];
      cell.textContent = isOne ? "1" : "0";
      cell.style.background = isOne ? "rgba(0,255,65,0.25)" : "var(--bg3)";
      cell.style.color = isOne ? "var(--green)" : "var(--text-muted)";
      cell.style.borderColor = isOne ? "rgba(0,255,65,0.4)" : "var(--border)";
    }

    const oneCount = pkvBits.filter(Boolean).length;
    document.getElementById("pkv-bit-count").textContent =
      `${oneCount} of 256 bits set`;

    const binEl = document.getElementById("pkv-binary");
    binEl.innerHTML = Array.from({ length: 32 }, (_, byteIdx) => {
      const chunk = binaryStr.slice(byteIdx * 8, byteIdx * 8 + 8);
      const col = byteIdx % 2 === 0 ? "var(--green)" : "rgba(0,255,65,0.5)";
      return `<span style="color:${col};margin-right:3px;">${chunk}</span>`;
    }).join("");

    const hexEl = document.getElementById("pkv-hex");
    if (document.activeElement !== hexEl) {
      hexEl.value = hex;
    }

    const decEl = document.getElementById("pkv-decimal");

    if (document.activeElement !== decEl) {
      decEl.value = bigint.toString();
    }
    const statusEl = document.getElementById("pkv-range-status");
    if (bigint === 0n) {
      statusEl.innerHTML = `<span style="color:var(--red);">ZERO - not a valid private key (must be ≥ 1)</span>`;
    } else if (bigint >= SECP256K1_N) {
      statusEl.innerHTML = `<span style="color:var(--red);">TOO LARGE - exceeds curve order N, not a valid private key</span>`;
    } else {
      const pct = Number((bigint * 10000n) / SECP256K1_N) / 100;
      statusEl.innerHTML = `<span style="color:var(--green);">✓ VALID private key &nbsp;-&nbsp; at ${pct.toFixed(4)}% of the valid range</span>`;
    }
  }

  function pkvBuildGrid() {
    const grid = document.getElementById("pkv-grid");
    grid.innerHTML = "";
    for (let i = 0; i < 256; i++) {
      const cell = document.createElement("div");
      cell.style.cssText = `
            aspect-ratio:1;display:flex;align-items:center;justify-content:center;
            border:1px solid var(--border);border-radius:2px;cursor:pointer;
            font-family:var(--font-mono);font-size:9px;font-weight:600;
            transition:background 0.08s,color 0.08s;
          `;
      cell.dataset.bit = i;
      cell.addEventListener("click", () => {
        pkvBits[i] = !pkvBits[i];
        pkvRender();
      });
      grid.appendChild(cell);
    }
  }

  document.getElementById("pkv-random").addEventListener("click", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    pkvHexToBits(bytesToHex(bytes));
    pkvRender();
  });

  document.getElementById("pkv-reset").addEventListener("click", () => {
    pkvBits.fill(false);
    pkvRender();
  });

  document.getElementById("pkv-hex").addEventListener("input", (e) => {
    const raw = e.target.value.trim().replace(/\s/g, "").toLowerCase();
    if (/^[0-9a-f]{1,64}$/.test(raw)) {
      pkvHexToBits(raw);
      pkvRender();
    }
  });

  document.getElementById("pkv-hex-copy").addEventListener("click", () => {
    copyText(pkvBitsToHex(), document.getElementById("pkv-hex-copy"));
  });

  document.getElementById("pkv-dec-copy").addEventListener("click", () => {
    const bigint = bytesToBigInt(hexToBytes(pkvBitsToHex()));
    copyText(bigint.toString(), document.getElementById("pkv-dec-copy"));
  });

  document.getElementById("pkv-decimal").addEventListener("input", (e) => {
    const raw = e.target.value.trim();
    if (!raw) return;
    if (!/^\d+$/.test(raw)) return;
    try {
      const n = BigInt(raw);
      if (n < 0n) return;
      const hex = n.toString(16).padStart(64, "0").slice(-64);
      pkvHexToBits(hex);
      pkvRender();
    } catch (_) {}
  });

  pkvBuildGrid();
  pkvRender();
}

export {
  generateMnemonicFromString,
  generateMnemonicWithDice,
  generateWalletFromMnemonic,
  deriveMultipleAddresses,
  validateMnemonic,
  validateRoundTrip,
  entropyToMnemonic,
  mnemonicToSeed,
  privateKeyToPublicKey,
  privateKeyToWIF,
  pubKeyToLegacy,
  pubKeyToNativeSegwit,
  pubKeyToTaproot,
  hexToBytes,
  bytesToHex,
  bytesToBigInt,
};

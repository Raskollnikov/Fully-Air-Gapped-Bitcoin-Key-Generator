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
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bigIntToBytes32(n) {
  const hex = n.toString(16).padStart(64, "0");
  return hexToBytes(hex);
}

function bytesToBigInt(bytes) {
  return BigInt("0x" + bytesToHex(bytes));
}

function concatBytes(...arrays) {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
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
  const len = msg.length;
  const bitLen = len * 8;
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
      el = h4;
    let ar = h0,
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

  const result = new Uint8Array(20);
  const rv = new DataView(result.buffer);
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
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data));
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
    { name: "PBKDF2", salt: enc.encode(salt), iterations, hash: "SHA-512" },
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
  if (!compressed) {
    return concatBytes(
      new Uint8Array([0x04]),
      bigIntToBytes32(x),
      bigIntToBytes32(y),
    );
  }
  const prefix = (y & 1n) === 0n ? 0x02 : 0x03;
  return concatBytes(new Uint8Array([prefix]), bigIntToBytes32(x));
}

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes) {
  let num = bytesToBigInt(bytes);
  let result = "";
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

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATOR = [
  0x3b6a57b2n,
  0x26508e6dn,
  0x1ea119fan,
  0x3d4233ddn,
  0x2a1462b3n,
];

function bech32Polymod(values) {
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

function bech32HrpExpand(hrp) {
  const result = [];
  for (const c of hrp) result.push(c.charCodeAt(0) >> 5);
  result.push(0);
  for (const c of hrp) result.push(c.charCodeAt(0) & 31);
  return result;
}

function convertbits(data, frombits, tobits, pad = true) {
  let acc = 0,
    bits = 0;
  const result = [];
  const maxv = (1 << tobits) - 1;
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

function bech32Encode(hrp, data) {
  const combined = [...bech32HrpExpand(hrp), ...data];
  const checksum = bech32Polymod([...combined, 0, 0, 0, 0, 0, 0]) ^ 1n;
  let result = hrp + "1";
  for (const d of data) result += BECH32_CHARSET[d];
  for (let p = 0; p < 6; p++)
    result += BECH32_CHARSET[Number((checksum >> BigInt(5 * (5 - p))) & 31n)];
  return result;
}

async function pubKeyToLegacy(pubKey) {
  const h160 = await hash160(pubKey);
  const payload = concatBytes(new Uint8Array([0x00]), h160);
  return base58Check(payload);
}

async function pubKeyToSegwit(pubKey) {
  const h160 = await hash160(pubKey);
  const redeemScript = concatBytes(new Uint8Array([0x00, 0x14]), h160);
  const scriptHash = await hash160(redeemScript);
  const payload = concatBytes(new Uint8Array([0x05]), scriptHash);
  return base58Check(payload);
}

async function pubKeyToNativeSegwit(pubKey) {
  const h160 = await hash160(pubKey);
  const words = [0, ...convertbits(h160, 8, 5)];
  return bech32Encode("bc", words);
}

const BECH32M_CONST = 0x2bc830a3n;

function bech32mEncode(hrp, data) {
  const combined = [...bech32HrpExpand(hrp), ...data];
  const checksum =
    bech32Polymod([...combined, 0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST;
  let result = hrp + "1";
  for (const d of data) result += BECH32_CHARSET[d];
  for (let p = 0; p < 6; p++)
    result += BECH32_CHARSET[Number((checksum >> BigInt(5 * (5 - p))) & 31n)];
  return result;
}

function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

async function pubKeyToTaproot(pubKey) {
  if (pubKey.length !== 33) throw new Error("pubkey must be 33 bytes");
  if (pubKey[0] !== 0x02 && pubKey[0] !== 0x03) {
    throw new Error("pubkey must be compressed (02/03 prefix)");
  }

  const xOnly = pubKey.slice(1);
  const x = bytesToBigInt(xOnly);

  const y_sq = (x * x * x + 7n) % P;
  if (modPow(y_sq, (P - 1n) / 2n, P) !== 1n) {
    throw new Error("x coordinate is not on secp256k1 - invalid public key");
  }
  let y = modPow(y_sq, (P + 1n) / 4n, P);
  if (y % 2n !== 0n) y = P - y;

  const tag = new TextEncoder().encode("TapTweak");
  const tagHash = await sha256(tag);
  const tweakInput = concatBytes(tagHash, tagHash, xOnly);
  const tweak = await sha256(tweakInput);
  const t = bytesToBigInt(tweak) % N;

  const G = [Gx, Gy];
  const internalPoint = [x, y];
  const tweakPoint = pointMul(t, G);
  const outputPoint = pointAdd(internalPoint, tweakPoint);

  if (outputPoint === null) {
    throw new Error("tweak produced point at infinity - astronomically rare");
  }

  const outputKey = bigIntToBytes32(outputPoint[0]);
  const words = [1, ...convertbits(outputKey, 8, 5)];
  return bech32mEncode("bc", words);
}

function privateKeyToWIF(privKey, compressed = true) {
  const keyBytes = bigIntToBytes32(privKey);
  const prefix = new Uint8Array([0x80]);
  const suffix = compressed ? new Uint8Array([0x01]) : new Uint8Array([]);
  return base58Check(concatBytes(prefix, keyBytes, suffix));
}

export function validateWordlist() {
  if (WORDLIST.length !== 2048) throw new Error("invalid wordlist");
}

export async function generateMnemonic(strength = 128, extraEntropy = null) {
  if (![128, 160, 192, 224, 256].includes(strength)) {
    throw new Error("strength must be 128, 160, 192, 224, or 256");
  }

  const csprng = crypto.getRandomValues(new Uint8Array(strength / 8));

  if (!extraEntropy || extraEntropy.length === 0) {
    return entropyToMnemonic(csprng);
  }

  const tsBuf = new Uint8Array(8);
  new DataView(tsBuf.buffer).setFloat64(0, performance.now(), false);

  const combined = concatBytes(csprng, extraEntropy, tsBuf);
  const mixed = new Uint8Array(await crypto.subtle.digest("SHA-256", combined));

  return entropyToMnemonic(mixed.slice(0, strength / 8));
}

export async function entropyToMnemonic(entropy) {
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
  for (let i = 0; i < allBits.length; i += 11) {
    words.push(WORDLIST[parseInt(allBits.slice(i, i + 11), 2)]);
  }
  return words.join(" ");
}

export async function mnemonicToSeed(mnemonic, passphrase = "") {
  return pbkdf2(
    mnemonic.normalize("NFKD"),
    "mnemonic" + passphrase.normalize("NFKD"),
    2048,
    64,
  );
}

export async function validateMnemonic(mnemonic) {
  try {
    const words = mnemonic.trim().toLowerCase().split(/\s+/);
    if (![12, 15, 18, 21, 24].includes(words.length)) return false;
    for (const word of words) {
      if (!WORDLIST.includes(word)) return false;
    }
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
    const parentPub = privateKeyToPublicKey(bytesToBigInt(parentKey));
    data = concatBytes(parentPub, indexBytes);
  }

  const I = await hmacSha512(parentChainCode, data);
  const IL = I.slice(0, 32);
  const IR = I.slice(32);
  const ILint = bytesToBigInt(IL);

  if (ILint >= N)
    throw new Error(
      "BIP32: derived key IL >= N (invalid, astronomically rare)",
    );

  const childKey = (ILint + bytesToBigInt(parentKey)) % N;

  if (childKey === 0n)
    throw new Error(
      "BIP32: derived child key is zero (invalid, astronomically rare)",
    );

  return { key: bigIntToBytes32(childKey), chainCode: IR };
}

async function derivePath(seed, path) {
  const I = await hmacSha512(new TextEncoder().encode("Bitcoin seed"), seed);
  let key = I.slice(0, 32);
  let chainCode = I.slice(32);

  const parts = path.replace("m/", "").split("/");
  for (const part of parts) {
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
    description: "Original Bitcoin address format",
    color: "#f7931a",
  },
  SEGWIT: {
    name: "SegWit (P2SH)",
    prefix: "3",
    path: "m/49'/0'/0'/0/0",
    description: "Backward-compatible SegWit",
    color: "#00d4aa",
  },
  NATIVE_SEGWIT: {
    name: "Native SegWit (Bech32)",
    prefix: "bc1q",
    path: "m/84'/0'/0'/0/0",
    description: "Lowest fees, modern format",
    color: "#7c3aed",
  },
  TAPROOT: {
    name: "Taproot (P2TR)",
    prefix: "bc1p",
    path: "m/86'/0'/0'/0/0",
    description: "Taproot keypath, most private, lowest fees",
    color: "#f97316",
  },
};

export async function generateWalletFromMnemonic(
  mnemonic,
  passphrase = "",
  walletType = "LEGACY",
  accountIndex = 0,
  addressIndex = 0,
) {
  const seed = await mnemonicToSeed(mnemonic, passphrase);
  const typeConfig = WALLET_TYPES[walletType];

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
    typeName: typeConfig.name,
  };
}

export async function generateRandomWallet(
  walletType = "LEGACY",
  wordCount = 12,
  passphrase = "",
  extraEntropy = null,
) {
  const strength = wordCount === 24 ? 256 : 128;
  const mnemonic = await generateMnemonic(strength, extraEntropy);
  return generateWalletFromMnemonic(mnemonic, passphrase, walletType);
}

export async function deriveMultipleAddresses(
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
      path = customPath.trim().replace(/\/\d+$/, "") + `/${addrIndex}`;
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

export function isOnline() {
  return navigator.onLine;
}

export async function validateRoundTrip(wallet) {
  const errors = [];

  try {
    const wif = wallet.privateKeyWIF;
    let num = 0n;
    for (const char of wif) {
      const idx = BASE58.indexOf(char);
      if (idx < 0) {
        errors.push("invalid WIF character");
        break;
      }
      num = num * 58n + BigInt(idx);
    }

    const hexStr = num.toString(16).padStart(76, "0");
    const decoded = hexToBytes(hexStr.length % 2 ? "0" + hexStr : hexStr);
    const buf38 = new Uint8Array(38);
    buf38.set(decoded.slice(Math.max(0, decoded.length - 38)));
    if (buf38[0] !== 0x80) {
      errors.push("WIF version byte invalid");
      return { valid: false, errors };
    }
    const keyBytes = buf38.slice(1, 33);
    const privKeyBigInt = bytesToBigInt(keyBytes);
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

  const mnemonicOk = await validateMnemonic(wallet.mnemonic);
  if (!mnemonicOk) errors.push("mnemonic BIP39 checksum invalid");

  if (wallet.privateKeyWIF.length < 51 || wallet.privateKeyWIF.length > 53) {
    errors.push(`WIF length suspicious: ${wallet.privateKeyWIF.length} chars`);
  }

  return { valid: errors.length === 0, errors };
}

export function secureWipe(obj) {
  if (typeof obj !== "object" || obj === null) return;
  const zeros =
    "0000000000000000000000000000000000000000000000000000000000000000";
  for (const key in obj) {
    const v = obj[key];
    if (typeof v === "string") {
      obj[key] = zeros.repeat(Math.ceil(v.length / 64)).slice(0, v.length);
    } else if (v instanceof Uint8Array || v instanceof Uint32Array) {
      v.fill(0);
    } else if (typeof v === "bigint") {
      obj[key] = 0n;
    } else if (Array.isArray(v)) {
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

export function secureWipeAll(walletsArray) {
  if (Array.isArray(walletsArray)) {
    walletsArray.forEach((w) => secureWipe(w));
    walletsArray.length = 0;
  }
  const sensitive = [
    "results-area",
    "print-area",
    "verify-mnemonic",
    "dice-input",
    "passphrase",
    "import-passphrase",
    "string-input",
  ];
  sensitive.forEach((id) => {
    if (typeof document === "undefined") return;
    const el = document.getElementById(id);
    if (!el) return;
    if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") el.value = "";
    else el.innerHTML = "";
  });
}

export function diceToEntropy(diceString, minRolls = 99) {
  const rolls = diceString
    .trim()
    .split(/[\s,;.|-]+/)
    .map(Number)
    .filter((n) => Number.isInteger(n) && n >= 1 && n <= 6);

  if (rolls.length < minRolls) {
    throw new Error(
      `you need at least ${minRolls} dice rolls for 128-bit security, got ${rolls.length}.`,
    );
  }

  let n = 0n;
  for (const r of rolls) {
    n = n * 6n + BigInt(r - 1);
  }

  const bytes = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return bytes;
}

export function validateDiceInput(diceString) {
  const rolls = diceString
    .trim()
    .split(/[\s,;.|-]+/)
    .map(Number)
    .filter((n) => Number.isInteger(n) && n >= 1 && n <= 6);
  const invalid = diceString
    .trim()
    .split(/[\s,;.|-]+/)
    .filter((t) => {
      const n = Number(t);
      return t !== "" && (isNaN(n) || n < 1 || n > 6);
    });
  return {
    count: rolls.length,
    valid: rolls.length >= 99,
    invalidTokens: invalid,
    entropyBits: Math.floor(rolls.length * Math.log2(6)),
  };
}

export async function mixEntropy(csrngBytes, userBytes) {
  const tsBuf = new Uint8Array(8);
  new DataView(tsBuf.buffer).setFloat64(0, performance.now(), false);

  const combined = new Uint8Array(csrngBytes.length + userBytes.length + 8);
  combined.set(csrngBytes, 0);
  combined.set(userBytes, csrngBytes.length);
  combined.set(tsBuf, csrngBytes.length + userBytes.length);

  return new Uint8Array(await crypto.subtle.digest("SHA-256", combined));
}

export async function generateMnemonicFromString(inputString, wordCount = 24) {
  if (!inputString || inputString.length === 0) {
    throw new Error("input string cannot be empty");
  }

  const strength = wordCount === 24 ? 32 : 16;
  const encoded = new TextEncoder().encode(inputString);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", encoded));
  const entropy = hash.slice(0, strength);

  return entropyToMnemonic(entropy);
}
export async function generateMnemonicWithDice(
  diceString,
  wordCount = 12,
  walletIndex = 0,
  deterministic = false,
) {
  const strength = wordCount === 24 ? 32 : 16;

  const csrng = crypto.getRandomValues(new Uint8Array(strength));

  const dice = diceToEntropy(diceString, deterministic ? 50 : 99);

  if (deterministic) {
    const indexBuf = new Uint8Array(4);
    new DataView(indexBuf.buffer).setUint32(0, walletIndex, false);
    const base = dice.slice(0, strength);
    const combined = new Uint8Array(strength + 1 + 4);
    combined.set(base, 0);
    combined[strength] = 0x00;
    combined.set(indexBuf, strength + 1);
    const mixed = new Uint8Array(
      await crypto.subtle.digest("SHA-256", combined),
    );
    return entropyToMnemonic(mixed.slice(0, strength));
  }
  const indexBuf = new Uint8Array(4);
  new DataView(indexBuf.buffer).setUint32(0, walletIndex, false);

  const combined = new Uint8Array(strength + strength + 4);
  combined.set(csrng, 0);
  combined.set(dice.slice(0, strength), strength);
  combined.set(indexBuf, strength * 2);

  const mixed = new Uint8Array(await crypto.subtle.digest("SHA-256", combined));

  const entropy = mixed.slice(0, strength);
  return entropyToMnemonic(entropy);
}

export function collectEntropyFromEvents() {
  return new Promise((resolve) => {
    const samples = [];
    let count = 0;
    const target = 30;

    const handler = (e) => {
      samples.push(
        ((e.clientX || 0) * 31337 + (e.clientY || 0) * 1337) ^
          Date.now() ^
          Math.round(performance.now() * 1000),
      );
      count++;
      if (count >= target) {
        document.removeEventListener("mousemove", handler);
        document.removeEventListener("keypress", handler);
        resolve(samples);
      }
    };

    document.addEventListener("mousemove", handler, { passive: true });
    document.addEventListener("keypress", handler, { passive: true });
    setTimeout(() => {
      document.removeEventListener("mousemove", handler);
      document.removeEventListener("keypress", handler);
      resolve(samples);
    }, 15000);
  });
}

export {
  bytesToHex,
  hexToBytes,
  bigIntToBytes32,
  bytesToBigInt,
  concatBytes,
  sha256,
  sha256d,
  ripemd160,
  hash160,
  privateKeyToPublicKey,
  base58Encode,
  base58Check,
  bech32Encode,
  convertbits,
  pubKeyToLegacy,
  pubKeyToSegwit,
  pubKeyToNativeSegwit,
  privateKeyToWIF,
  WORDLIST,
  pubKeyToTaproot,
  bech32mEncode,
};

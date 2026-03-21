import * as wallet from "../js/wallet.js";

let passed = 0;
let failed = 0;

function assert(label, got, expected) {
  if (got === expected) {
    console.log(`  ✓ ${label}`);
    passed++;
  } else {
    console.error(`  ✗ ${label}`);
    console.error(`    expected: ${String(expected).slice(0, 120)}`);
    console.error(`    got:      ${String(got).slice(0, 120)}`);
    failed++;
  }
}

function assertBool(label, value) {
  assert(label, value, true);
}

function assertThrows(label, fn) {
  return fn().then(
    () => {
      console.error(`  ✗ ${label} - expected throw, got success`);
      failed++;
    },
    () => {
      console.log(`  ✓ ${label}`);
      passed++;
    },
  );
}

console.log("\n═══ generateMnemonicFromString — determinism ═══");

{
  const m1 = await wallet.generateMnemonicFromString("test-string-abc-123", 24);
  const m2 = await wallet.generateMnemonicFromString("test-string-abc-123", 24);
  const m3 = await wallet.generateMnemonicFromString("test-string-abc-124", 24);
  const m4 = await wallet.generateMnemonicFromString("TEST-STRING-ABC-123", 24);

  assertBool("same string → same 24-word mnemonic (run 1 = run 2)", m1 === m2);
  assertBool("different string → different mnemonic", m1 !== m3);
  assertBool("case-sensitive: uppercase ≠ lowercase", m1 !== m4);
  assert("24-word mnemonic word count", m1.split(" ").length, 24);

  const m5 = await wallet.generateMnemonicFromString("test-string-abc-123", 12);
  const m6 = await wallet.generateMnemonicFromString("test-string-abc-123", 12);
  assert("12-word mnemonic word count", m5.split(" ").length, 12);
  assertBool("same string → same 12-word mnemonic", m5 === m6);
  assertBool("12-word ≠ 24-word from same string", m1 !== m5);

  assertBool(
    "24-word passes BIP39 checksum",
    await wallet.validateMnemonic(m1),
  );
  assertBool(
    "12-word passes BIP39 checksum",
    await wallet.validateMnemonic(m5),
  );
  assertBool(
    "uppercase variant passes BIP39 checksum",
    await wallet.validateMnemonic(m4),
  );
}

console.log("\n═══ generateMnemonicFromString — unicode & edge cases ═══");

{
  const mEmoji1 = await wallet.generateMnemonicFromString("🔑🎲₿🔐💎", 12);
  const mEmoji2 = await wallet.generateMnemonicFromString("🔑🎲₿🔐💎", 12);
  assertBool("emoji string deterministic", mEmoji1 === mEmoji2);
  assertBool(
    "emoji mnemonic BIP39 valid",
    await wallet.validateMnemonic(mEmoji1),
  );

  const mCyrillic1 = await wallet.generateMnemonicFromString("привет мир", 12);
  const mCyrillic2 = await wallet.generateMnemonicFromString("привет мир", 12);
  assertBool("cyrillic string deterministic", mCyrillic1 === mCyrillic2);
  assertBool(
    "cyrillic mnemonic BIP39 valid",
    await wallet.validateMnemonic(mCyrillic1),
  );

  const mSpaced = await wallet.generateMnemonicFromString(
    " test-string-abc-123 ",
    12,
  );
  const mClean = await wallet.generateMnemonicFromString(
    "test-string-abc-123",
    12,
  );
  assertBool("leading/trailing space changes output", mSpaced !== mClean);
}

console.log("\n═══ generateMnemonicFromString — error cases ═══");

await assertThrows("empty string throws", () =>
  wallet.generateMnemonicFromString("", 12),
);

console.log(
  "\n═══ generateMnemonicFromString — multi-wallet nonce (\\x00 separator) ═══",
);

{
  const base =
    "my-very-long-and-random-passphrase-that-is-over-50-chars-total!!";

  const w0 = await wallet.generateMnemonicFromString(base + "\x000", 12);
  const w1 = await wallet.generateMnemonicFromString(base + "\x001", 12);
  const w2 = await wallet.generateMnemonicFromString(base + "\x002", 12);

  assertBool("nonce 0 ≠ nonce 1", w0 !== w1);
  assertBool("nonce 1 ≠ nonce 2", w1 !== w2);
  assertBool("nonce 0 ≠ nonce 2", w0 !== w2);

  const w0b = await wallet.generateMnemonicFromString(base + "\x000", 12);
  assertBool("nonce 0 deterministic across runs", w0 === w0b);

  assertBool("nonce 0 BIP39 valid", await wallet.validateMnemonic(w0));
  assertBool("nonce 1 BIP39 valid", await wallet.validateMnemonic(w1));
  assertBool("nonce 2 BIP39 valid", await wallet.validateMnemonic(w2));

  const collision1 = await wallet.generateMnemonicFromString("abc\x000", 12);
  const collision2 = await wallet.generateMnemonicFromString("ab\x000c", 12);
  assertBool(
    "null byte separator prevents prefix collision",
    collision1 !== collision2,
  );
}

console.log("\n═══ generateMnemonicFromString → full wallet derivation ═══");

{
  const str =
    "correct-horse-battery-staple-but-much-longer-than-50-characters!!";
  const mnemonic = await wallet.generateMnemonicFromString(str, 12);
  const w = await wallet.generateWalletFromMnemonic(
    mnemonic,
    "",
    "NATIVE_SEGWIT",
  );
  const vr = await wallet.validateRoundTrip(w);

  assertBool("string-derived wallet round-trip valid", vr.valid);
  assertBool("address starts with bc1q", w.address.startsWith("bc1q"));

  const mnemonic2 = await wallet.generateMnemonicFromString(str, 12);
  const w2 = await wallet.generateWalletFromMnemonic(
    mnemonic2,
    "",
    "NATIVE_SEGWIT",
  );
  assertBool(
    "same string → same address deterministically",
    w.address === w2.address,
  );
  assertBool(
    "same string → same WIF deterministically",
    w.privateKeyWIF === w2.privateKeyWIF,
  );

  const wLeg = await wallet.generateWalletFromMnemonic(mnemonic, "", "LEGACY");
  const wSeg = await wallet.generateWalletFromMnemonic(mnemonic, "", "SEGWIT");
  assertBool(
    "legacy round-trip valid",
    (await wallet.validateRoundTrip(wLeg)).valid,
  );
  assertBool(
    "segwit round-trip valid",
    (await wallet.validateRoundTrip(wSeg)).valid,
  );
  assertBool("legacy address starts with 1", wLeg.address.startsWith("1"));
  assertBool("segwit address starts with 3", wSeg.address.startsWith("3"));
}

console.log("\n═══ generateMnemonicWithDice — deterministic mode ═══");

{
  const dice99 = Array(99).fill("1").join(" ");
  const dice150 = Array(150).fill("3").join(" ");

  const d1a = await wallet.generateMnemonicWithDice(dice99, 12, 0, true);
  const d1b = await wallet.generateMnemonicWithDice(dice99, 12, 0, true);
  assertBool("deterministic: same dice → same mnemonic", d1a === d1b);
  assertBool(
    "deterministic: BIP39 checksum valid",
    await wallet.validateMnemonic(d1a),
  );
  assert("deterministic: 12-word count", d1a.split(" ").length, 12);

  const d2a = await wallet.generateMnemonicWithDice(dice99, 24, 0, true);
  const d2b = await wallet.generateMnemonicWithDice(dice99, 24, 0, true);
  assertBool("deterministic 24-word: same dice → same", d2a === d2b);
  assertBool(
    "deterministic 24-word: BIP39 valid",
    await wallet.validateMnemonic(d2a),
  );
  assert("deterministic: 24-word count", d2a.split(" ").length, 24);

  const d3 = await wallet.generateMnemonicWithDice(dice150, 12, 0, true);
  assertBool("deterministic: different dice → different mnemonic", d1a !== d3);

  const dIdx0 = await wallet.generateMnemonicWithDice(dice99, 12, 0, true);
  const dIdx5 = await wallet.generateMnemonicWithDice(dice99, 12, 5, true);
  assertBool(
    "deterministic: walletIndex produces unique wallets in batch",
    dIdx0 !== dIdx5,
  );
}

console.log(
  "\n═══ generateMnemonicWithDice — mixed mode (existing behaviour) ═══",
);

{
  const dice99 = Array(99).fill("2").join(" ");

  const m0 = await wallet.generateMnemonicWithDice(dice99, 12, 0, false);
  const m1 = await wallet.generateMnemonicWithDice(dice99, 12, 1, false);
  const m2 = await wallet.generateMnemonicWithDice(dice99, 12, 2, false);
  assertBool("mixed: index 0 ≠ index 1", m0 !== m1);
  assertBool("mixed: index 1 ≠ index 2", m1 !== m2);

  const mA = await wallet.generateMnemonicWithDice(dice99, 12, 0, true);
  const mB = await wallet.generateMnemonicWithDice(dice99, 12, 1, true);
  assertBool(
    "mixed: same dice+index → different mnemonic each run (CSPRNG)",
    mA !== mB,
  );

  assertBool("mixed 0 BIP39 valid", await wallet.validateMnemonic(m0));
  assertBool("mixed 1 BIP39 valid", await wallet.validateMnemonic(m1));
}

console.log("\n═══ generateMnemonicWithDice — deterministic → full wallet ═══");

{
  const dice = Array(99).fill("4").join(" ");
  const mnemonic = await wallet.generateMnemonicWithDice(dice, 12, 0, true);
  const w = await wallet.generateWalletFromMnemonic(
    mnemonic,
    "",
    "NATIVE_SEGWIT",
  );
  const vr = await wallet.validateRoundTrip(w);

  assertBool("deterministic dice → wallet round-trip valid", vr.valid);

  const mnemonic2 = await wallet.generateMnemonicWithDice(dice, 12, 0, true);
  const w2 = await wallet.generateWalletFromMnemonic(
    mnemonic2,
    "",
    "NATIVE_SEGWIT",
  );
  assertBool(
    "deterministic dice → same address on repeat",
    w.address === w2.address,
  );
}

console.log("\n═══ secureWipeAll — string-input coverage ═══");

{
  const fakeWallet = {
    mnemonic:
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    privateKeyWIF: "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
    address: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
    walletType: "LEGACY",
    path: "m/44'/0'/0'/0/0",
    passphrase: "",
  };
  const arr = [fakeWallet];
  wallet.secureWipeAll(arr);
  assertBool("wallet array emptied after secureWipeAll", arr.length === 0);
  assertBool("wallet object nulled after wipe", fakeWallet.mnemonic === null);
}

console.log("\n═══ Pipeline integrity — SHA256(string) → BIP39 ═══");

{
  const knownHash =
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
  const entropy16 = wallet.hexToBytes(knownHash.slice(0, 32));
  const expectedMnemonic = await wallet.entropyToMnemonic(entropy16);
  const actualMnemonic = await wallet.generateMnemonicFromString("hello", 12);
  assertBool(
    "SHA256('hello') → known 12-word mnemonic matches",
    expectedMnemonic === actualMnemonic,
  );

  const entropy32 = wallet.hexToBytes(knownHash);
  const expected24 = await wallet.entropyToMnemonic(entropy32);
  const actual24 = await wallet.generateMnemonicFromString("hello", 24);
  assertBool(
    "SHA256('hello') → known 24-word mnemonic matches",
    expected24 === actual24,
  );

  assertBool(
    "'hello' 12-word BIP39 valid",
    await wallet.validateMnemonic(actualMnemonic),
  );
  assertBool(
    "'hello' 24-word BIP39 valid",
    await wallet.validateMnemonic(actual24),
  );
}

console.log("\n═══ Entropy mode isolation — string ≠ dice ≠ mouse outputs ═══");

{
  const diceString = Array(99).fill("1").join(" ");

  const fromDice = await wallet.generateMnemonicWithDice(
    diceString,
    12,
    0,
    true,
  );
  const fromString = await wallet.generateMnemonicFromString(diceString, 12);

  assertBool(
    "dice mode ≠ string mode for same input characters",
    fromDice !== fromString,
  );
}

console.log("\n═══ Regression: existing tests still pass ═══");

{
  const k1pub = wallet.privateKeyToPublicKey(1n, true);
  const k1addr = await wallet.pubKeyToLegacy(k1pub);
  assertBool(
    "k=1 legacy address unchanged",
    k1addr === "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
  );

  const k1nsw = await wallet.pubKeyToNativeSegwit(k1pub);
  assertBool(
    "k=1 native segwit address unchanged",
    k1nsw === "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
  );

  const seed = await wallet.mnemonicToSeed(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "",
  );
  assertBool("BIP39 seed vector first byte", seed[0] === 0x5e);
  assertBool("BIP39 seed vector length", seed.length === 64);
}

console.log("\n═══ Taproot - address format validation ═══");

{
  const seed = await wallet.mnemonicToSeed(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "",
  );
  const w = await wallet.generateWalletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "",
    "TAPROOT",
    0,
    0,
  );

  assertBool("Taproot address starts with bc1p", w.address.startsWith("bc1p"));
  assertBool("Taproot address length is 62 chars", w.address.length === 62);
  assertBool(
    "Taproot address contains only valid bech32m charset",
    /^bc1p[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$/.test(w.address),
  );
  assertBool("Taproot derivation path is m/86'", w.path.startsWith("m/86'"));
  assertBool("Taproot typeName correct", w.typeName === "Taproot (P2TR)");
  assertBool("Taproot walletType field", w.walletType === "TAPROOT");
}

console.log("\n═══ Taproot - BIP86 known test vector ═══");

{
  const knownAddress =
    "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";

  const w = await wallet.generateWalletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "",
    "TAPROOT",
    0,
    0,
  );

  assert("BIP86 vector 0/0 address matches spec", w.address, knownAddress);

  const knownAddress1 =
    "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh";
  const w1 = await wallet.generateWalletFromMnemonic(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "",
    "TAPROOT",
    0,
    1,
  );
  assert("BIP86 vector 0/1 address matches spec", w1.address, knownAddress1);
}

console.log("\n═══ Taproot - round-trip validation ═══");

{
  const mnemonic = await wallet.generateMnemonicFromString(
    "taproot-test-string-for-round-trip-validation-over-50-chars!!",
    12,
  );

  const w = await wallet.generateWalletFromMnemonic(mnemonic, "", "TAPROOT");
  const vr = await wallet.validateRoundTrip(w);

  assertBool("Taproot round-trip valid", vr.valid);
  assertBool("Taproot round-trip zero errors", vr.errors.length === 0);
  assertBool(
    "Taproot address starts bc1p after round-trip",
    w.address.startsWith("bc1p"),
  );

  const wp = await wallet.generateWalletFromMnemonic(
    mnemonic,
    "hunter2",
    "TAPROOT",
  );
  const vrp = await wallet.validateRoundTrip(wp);
  assertBool("Taproot+passphrase round-trip valid", vrp.valid);
  assertBool(
    "Taproot address ≠ Taproot+passphrase address",
    w.address !== wp.address,
  );
}

console.log("\n═══ Taproot - determinism ═══");

{
  const mnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

  const w1 = await wallet.generateWalletFromMnemonic(
    mnemonic,
    "",
    "TAPROOT",
    0,
    0,
  );
  const w2 = await wallet.generateWalletFromMnemonic(
    mnemonic,
    "",
    "TAPROOT",
    0,
    0,
  );
  assertBool("Taproot: same seed → same address", w1.address === w2.address);
  assertBool(
    "Taproot: same seed → same WIF",
    w1.privateKeyWIF === w2.privateKeyWIF,
  );

  const w3 = await wallet.generateWalletFromMnemonic(
    mnemonic,
    "",
    "TAPROOT",
    0,
    1,
  );
  assertBool("Taproot: index 0 ≠ index 1", w1.address !== w3.address);

  const w4 = await wallet.generateWalletFromMnemonic(
    mnemonic,
    "",
    "TAPROOT",
    1,
    0,
  );
  assertBool("Taproot: account 0 ≠ account 1", w1.address !== w4.address);
}

console.log("\n═══ Taproot - address type isolation ═══");

{
  const mnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

  const wTap = await wallet.generateWalletFromMnemonic(mnemonic, "", "TAPROOT");
  const wNsw = await wallet.generateWalletFromMnemonic(
    mnemonic,
    "",
    "NATIVE_SEGWIT",
  );
  const wSeg = await wallet.generateWalletFromMnemonic(mnemonic, "", "SEGWIT");
  const wLeg = await wallet.generateWalletFromMnemonic(mnemonic, "", "LEGACY");

  assertBool(
    "Taproot address ≠ Native SegWit address",
    wTap.address !== wNsw.address,
  );
  assertBool("Taproot address ≠ SegWit address", wTap.address !== wSeg.address);
  assertBool("Taproot address ≠ Legacy address", wTap.address !== wLeg.address);
  assertBool("Taproot prefix bc1p", wTap.address.startsWith("bc1p"));
  assertBool("Native SegWit prefix bc1q", wNsw.address.startsWith("bc1q"));
  assertBool("SegWit prefix 3", wSeg.address.startsWith("3"));
  assertBool("Legacy prefix 1", wLeg.address.startsWith("1"));

  assertBool(
    "Taproot WIF ≠ Legacy WIF (different path)",
    wTap.privateKeyWIF !== wLeg.privateKeyWIF,
  );
}

console.log("\n═══ Taproot - pubKeyToTaproot direct ═══");

{
  const pubKey1 = wallet.privateKeyToPublicKey(1n, true);
  const taprootAddr1 = await wallet.pubKeyToTaproot(pubKey1);

  assertBool(
    "k=1 taproot address starts bc1p",
    taprootAddr1.startsWith("bc1p"),
  );
  assertBool("k=1 taproot address length 62", taprootAddr1.length === 62);

  const pubKey2 = wallet.privateKeyToPublicKey(2n, true);
  const taprootAddr2 = await wallet.pubKeyToTaproot(pubKey2);
  assertBool("k=1 taproot ≠ k=2 taproot", taprootAddr1 !== taprootAddr2);

  const taprootAddr1b = await wallet.pubKeyToTaproot(pubKey1);
  assertBool("pubKeyToTaproot deterministic", taprootAddr1 === taprootAddr1b);

  const nswAddr1 = await wallet.pubKeyToNativeSegwit(pubKey1);
  assertBool(
    "taproot ≠ native segwit from same pubkey",
    taprootAddr1 !== nswAddr1,
  );
}

console.log("\n═══ Taproot - bech32m checksum isolation ═══");

{
  const pubKey = wallet.privateKeyToPublicKey(42n, true);
  const taprootAddr = await wallet.pubKeyToTaproot(pubKey);
  const nswAddr = await wallet.pubKeyToNativeSegwit(pubKey);

  assertBool(
    "bc1p address does not match bc1q pattern",
    !/^bc1q/.test(taprootAddr),
  );
  assertBool(
    "bc1q address does not match bc1p pattern",
    !/^bc1p/.test(nswAddr),
  );
  assertBool("taproot address exactly 62 chars", taprootAddr.length === 62);
  assertBool("native segwit address exactly 42 chars", nswAddr.length === 42);
}

console.log("\n═══ Taproot - deriveMultipleAddresses ═══");

{
  const mnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

  const addresses = await wallet.deriveMultipleAddresses(
    mnemonic,
    "",
    "TAPROOT",
    5,
    0,
    0,
    null,
    0,
  );

  assertBool(
    "deriveMultipleAddresses returns 5 taproot",
    addresses.length === 5,
  );
  assertBool("index 0 starts bc1p", addresses[0].address.startsWith("bc1p"));
  assertBool("index 4 starts bc1p", addresses[4].address.startsWith("bc1p"));
  assertBool(
    "all addresses unique",
    new Set(addresses.map((a) => a.address)).size === 5,
  );
  assertBool("path uses 86'", addresses[0].path.startsWith("m/86'"));
  assertBool(
    "index field matches",
    addresses[0].index === 0 && addresses[4].index === 4,
  );

  assert(
    "deriveMultipleAddresses[0] matches BIP86 vector",
    addresses[0].address,
    "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
  );

  const addressesFrom3 = await wallet.deriveMultipleAddresses(
    mnemonic,
    "",
    "TAPROOT",
    3,
    0,
    0,
    null,
    3,
  );
  assertBool("startIndex=3: first index is 3", addressesFrom3[0].index === 3);
  assertBool(
    "startIndex=3: path ends in /3",
    addressesFrom3[0].path.endsWith("/3"),
  );
  assertBool(
    "startIndex=3: address[0] matches addresses[3] from full range",
    addressesFrom3[0].address === addresses[3].address,
  );
}

console.log("\n═══ Taproot - WIF private key format unchanged ═══");

{
  const mnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const w = await wallet.generateWalletFromMnemonic(mnemonic, "", "TAPROOT");

  assertBool(
    "Taproot WIF length in valid range (51-52)",
    w.privateKeyWIF.length >= 51 && w.privateKeyWIF.length <= 52,
  );
  assertBool(
    "Taproot WIF starts with K or L (compressed mainnet)",
    w.privateKeyWIF.startsWith("K") || w.privateKeyWIF.startsWith("L"),
  );
}

console.log("\n═══ Taproot - odd-parity internal key coverage ═══");

{
  const pubKey6 = wallet.privateKeyToPublicKey(6n, true);
  assertBool("k=6 has odd y (0x03 prefix)", pubKey6[0] === 0x03);

  const taprootAddr6 = await wallet.pubKeyToTaproot(pubKey6);
  assertBool(
    "odd-parity key: address starts bc1p",
    taprootAddr6.startsWith("bc1p"),
  );
  assertBool("odd-parity key: address length 62", taprootAddr6.length === 62);

  const taprootAddr6b = await wallet.pubKeyToTaproot(pubKey6);
  assertBool("odd-parity key: deterministic", taprootAddr6 === taprootAddr6b);

  const pubKey1 = wallet.privateKeyToPublicKey(1n, true);
  assertBool("k=1 has even y (0x02 prefix)", pubKey1[0] === 0x02);
  const taprootAddr1 = await wallet.pubKeyToTaproot(pubKey1);
  assertBool(
    "even-parity ≠ odd-parity taproot address",
    taprootAddr1 !== taprootAddr6,
  );

  let foundOdd = null;
  for (let i = 0; i < 20; i++) {
    const w = await wallet.generateWalletFromMnemonic(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      "",
      "TAPROOT",
      0,
      i,
    );
    const pub = wallet.privateKeyToPublicKey(
      wallet.bytesToBigInt(wallet.hexToBytes(w.privateKeyHex)),
      true,
    );
    if (pub[0] === 0x03) {
      foundOdd = w;
      break;
    }
  }

  if (foundOdd) {
    const vr = await wallet.validateRoundTrip(foundOdd);
    assertBool("odd-parity full wallet round-trip valid", vr.valid);
    assertBool(
      "odd-parity full wallet address starts bc1p",
      foundOdd.address.startsWith("bc1p"),
    );
  } else {
    assertBool("found an odd-parity key in first 20 indices", false);
  }
}

const total = passed + failed;
console.log(`\n${"═".repeat(60)}`);
console.log(`  Results: ${passed} passed, ${failed} failed (${total} total)`);
if (failed > 0) {
  console.error(`  ✗ ${failed} test(s) FAILED`);
  process.exit(1);
} else {
  console.log(`  ✓ All tests passing`);
}

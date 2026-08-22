// Makes the same call an ad blocker makes when uncloaking canonical names.
// The claim under test is that this reaches nsIDNSService and bypasses SOCKS.
// If it does, the dns_udp counter moves. If it does not, the claim is false here.
const results = [];

async function probe(host, flags) {
  const t0 = Date.now();
  try {
    const r = await browser.dns.resolve(host, flags);
    results.push({ host, flags, ok: true, addrs: r.addresses, ms: Date.now() - t0 });
  } catch (e) {
    results.push({ host, flags, ok: false, err: String(e), ms: Date.now() - t0 });
  }
}

(async () => {
  // Ad blockers pass the canonical_name flag; a plain lookup is measured too,
  // so the difference between the two is visible.
  await probe("example.com", ["canonical_name"]);
  await probe("cname-test.nmp.invalid", ["canonical_name"]);
  await probe("mozilla.org", []);
  await probe("example.com", ["disable_ipv6", "canonical_name"]);
  // Leave the result somewhere the page can read it.
  await browser.storage.local.set({ nmpDnsProbe: results });
  console.log("NMP_DNSPROBE " + JSON.stringify(results));
})();

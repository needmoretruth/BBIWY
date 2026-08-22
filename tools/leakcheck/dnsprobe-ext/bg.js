// uBO가 "Uncloak canonical names"에서 하는 것과 같은 호출을 한다.
// 이 호출이 nsIDNSService로 내려가고, 그것이 SOCKS를 우회한다는 것이 문서의 주장이다.
// 우회하면 격리망 계수기의 dns_udp 가 올라간다. 안 올라가면 주장이 이 설정에서는 틀린 것이다.
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
  // uBO는 canonical_name 플래그를 쓴다. 평범한 해석도 함께 재서 차이를 본다.
  await probe("example.com", ["canonical_name"]);
  await probe("cname-test.nmp.invalid", ["canonical_name"]);
  await probe("mozilla.org", []);
  await probe("example.com", ["disable_ipv6", "canonical_name"]);
  // 결과를 페이지에서 읽을 수 있게 남긴다.
  await browser.storage.local.set({ nmpDnsProbe: results });
  console.log("NMP_DNSPROBE " + JSON.stringify(results));
})();

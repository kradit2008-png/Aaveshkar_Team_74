/**
 * Automated test suite for Identity Shield Node.js server.
 */

const http = require("http");
const assert = require("assert");
const { server } = require("../server");

const PORT = 3000;

function request(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          const json = JSON.parse(data);
          resolve({ status: res.statusCode, headers: res.headers, body: json });
        } catch (e) {
          resolve({ status: res.statusCode, headers: res.headers, raw: data });
        }
      });
    });
    req.on("error", reject);
    if (postData) {
      req.write(JSON.stringify(postData));
    }
    req.end();
  });
}

async function ensureServerRunning() {
  return new Promise((resolve) => {
    server.listen(PORT, "127.0.0.1", () => {
      resolve();
    });
    server.on("error", (err) => {
      if (err.code === "EADDRINUSE") {
        // Server already running on port 3000, which is fine
        resolve();
      } else {
        throw err;
      }
    });
  });
}

async function runTests() {
  await ensureServerRunning();
  console.log("[*] Running Node.js server automated tests...");

  // 1. Network info test
  const netRes = await request({
    host: "127.0.0.1",
    port: 3000,
    path: "/api/network-info",
    method: "GET",
  });
  assert.strictEqual(netRes.status, 200);
  assert.ok(netRes.body.primaryIp, "Must return primaryIp");
  assert.ok(netRes.body.networkUrl, "Must return networkUrl");
  console.log("  [+] PASS: /api/network-info returns LAN IP:", netRes.body.primaryIp);

  // 2. Stats test
  const statsRes = await request({
    host: "127.0.0.1",
    port: 3000,
    path: "/api/stats",
    method: "GET",
  });
  assert.strictEqual(statsRes.status, 200);
  assert.ok(typeof statsRes.body.total_identities === "number");
  console.log("  [+] PASS: /api/stats returns total identities:", statsRes.body.total_identities);

  // 3. Create alias test
  const createRes = await request(
    {
      host: "127.0.0.1",
      port: 3000,
      path: "/api/aliases",
      method: "POST",
      headers: { "Content-Type": "application/json" },
    },
    {
      service_name: "Mobile Test App",
      service_domain: "mobiletest.com",
      tier: "ephemeral",
      ttl_days: 7,
    }
  );
  assert.strictEqual(createRes.status, 201);
  assert.strictEqual(createRes.body.service_name, "Mobile Test App");
  const createdAlias = createRes.body.alias_email;
  console.log("  [+] PASS: /api/aliases created alias:", createdAlias);

  // 4. Trace authorized test
  const traceOk = await request(
    {
      host: "127.0.0.1",
      port: 3000,
      path: "/api/trace",
      method: "POST",
      headers: { "Content-Type": "application/json" },
    },
    {
      alias_email: createdAlias,
      sender_email: "support@mobiletest.com",
    }
  );
  assert.strictEqual(traceOk.status, 200);
  assert.strictEqual(traceOk.body.verdict, "FORWARD_ALLOWED");
  console.log("  [+] PASS: /api/trace verified authorized sender");

  // 5. Trace leak test with auto-revoke
  const traceLeak = await request(
    {
      host: "127.0.0.1",
      port: 3000,
      path: "/api/trace",
      method: "POST",
      headers: { "Content-Type": "application/json" },
    },
    {
      alias_email: createdAlias,
      sender_email: "promotions@broker-leak.net",
      auto_revoke: true,
    }
  );
  assert.strictEqual(traceLeak.status, 200);
  assert.strictEqual(traceLeak.body.verdict, "POTENTIAL_LEAK_OR_RESALE");
  assert.strictEqual(traceLeak.body.forwarding_action, "KILLED");
  // 6. Export vault test
  const exportRes = await request({
    host: "127.0.0.1",
    port: 3000,
    path: "/api/export",
    method: "GET",
  });
  assert.strictEqual(exportRes.status, 200);
  assert.ok(Array.isArray(exportRes.body), "Export body should be an array of identities");
  assert.ok(exportRes.headers["content-disposition"].includes("identity_shield_vault.json"));
  console.log("  [+] PASS: /api/export returns JSON vault with " + exportRes.body.length + " entries");

  // 7. Audit logs endpoint test
  const logsRes = await request({
    host: "127.0.0.1",
    port: 3000,
    path: "/api/logs?limit=10",
    method: "GET",
  });
  assert.strictEqual(logsRes.status, 200);
  assert.ok(Array.isArray(logsRes.body), "Audit logs should return an array");
  console.log("  [+] PASS: /api/logs returns " + logsRes.body.length + " audit log entries");

  // 8. Revoked alias trace test (verify dropped message)
  const traceRevoked = await request(
    {
      host: "127.0.0.1",
      port: 3000,
      path: "/api/trace",
      method: "POST",
      headers: { "Content-Type": "application/json" },
    },
    {
      alias_email: createdAlias,
      sender_email: "support@mobiletest.com",
    }
  );
  assert.strictEqual(traceRevoked.status, 200);
  assert.strictEqual(traceRevoked.body.verdict, "BLOCKED_REVOKED");
  console.log("  [+] PASS: /api/trace drops messages to revoked alias (BLOCKED_REVOKED)");

  // 9. Purge expired identities endpoint test
  const purgeRes = await request({
    host: "127.0.0.1",
    port: 3000,
    path: "/api/purge-expired",
    method: "POST",
  });
  assert.strictEqual(purgeRes.status, 200);
  assert.ok(typeof purgeRes.body.purged_count === "number");
  console.log("  [+] PASS: /api/purge-expired returns count:", purgeRes.body.purged_count);

  // 10. Reset demo endpoint test
  const resetRes = await request({
    host: "127.0.0.1",
    port: 3000,
    path: "/api/reset-demo",
    method: "POST",
  });
  assert.strictEqual(resetRes.status, 200);
  assert.strictEqual(resetRes.body.total_identities, 10);
  console.log("  [+] PASS: /api/reset-demo restored default vault with 10 identities");

  // 11. Threat intelligence scan test
  const scanRes = await request(
    {
      host: "127.0.0.1",
      port: 3000,
      path: "/api/threat-intel/scan",
      method: "POST",
      headers: { "Content-Type": "application/json" },
    },
    { alias_email: "netflix.8a3c94f1@relay.identityshield.local" }
  );
  assert.strictEqual(scanRes.status, 200);
  assert.ok(scanRes.body.exposure_score >= 0, "Exposure score must be numeric");
  assert.ok(Array.isArray(scanRes.body.matched_broker_networks), "Should list broker networks");
  console.log("  [+] PASS: /api/threat-intel/scan returned exposure level:", scanRes.body.exposure_level);

  // 12. Cryptographic PPID & blinded hash proof lab test
  const ppidRes = await request(
    {
      host: "127.0.0.1",
      port: 3000,
      path: "/api/crypto/ppid-proof",
      method: "POST",
      headers: { "Content-Type": "application/json" },
    },
    { email: "alice.security@enterprise.org" }
  );
  assert.strictEqual(ppidRes.status, 200);
  assert.strictEqual(ppidRes.body.collusion_linkable, false);
  assert.ok(ppidRes.body.client_a.ppid.startsWith("ppid_"), "Client A PPID format");
  assert.ok(ppidRes.body.client_b.ppid.startsWith("ppid_"), "Client B PPID format");
  console.log("  [+] PASS: /api/crypto/ppid-proof verified zero-collusion linkability");

  console.log("[✓] All Node.js integration tests PASSED successfully!");
  process.exit(0);
}

runTests().catch((err) => {
  console.error("[-] Test failure:", err);
  process.exit(1);
});

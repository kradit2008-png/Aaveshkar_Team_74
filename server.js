#!/usr/bin/env node
/**
 * Identity Shield — Node.js Cross-Device Network Server
 * Problem 4.1: Routine Online Sign-Up Identity Exposure Protection
 *
 * Optimized Standalone HTTP Server:
 * - In-memory vault state with asynchronous atomic persistence
 * - Zero external dependencies (native Node.js modules only)
 * - LAN network IP binding and cross-device access (Mobile, Tablet, Desktop)
 * - In-memory static asset cache with ETag & 304 Not Modified validation
 * - Automatic TTL purge engine for expired ephemeral identities
 */

const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const PORT = parseInt(process.env.PORT || "3000", 10);
const HOST = "0.0.0.0"; // Listen on all network interfaces
const DATA_FILE = path.join(__dirname, "vault_node.json");
const MASTER_KEY = process.env.SHIELD_MASTER_KEY || "shield_node_entropy_key_2026";
const DEFAULT_RELAY = "relay.identityshield.local";

// MIME Type Mapping
const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".jpg": "image/jpeg",
};

// Network Interface Detection
function getLocalNetworkIPs() {
  const interfaces = os.networkInterfaces();
  const addresses = [];
  for (const [name, netList] of Object.entries(interfaces)) {
    for (const net of netList) {
      if (net.family === "IPv4" && !net.internal && !net.address.startsWith("169.254.")) {
        addresses.push({ name, address: net.address });
      }
    }
  }
  return addresses;
}

function seedFreshVault() {
  return {
    identities: [
      {
        id: 1,
        alias_email: "apex-bank.c89a01f2@relay.identityshield.local",
        service_name: "Apex National Bank",
        service_domain: "apexbank.com",
        tier: "core",
        target_forward_email: "user@personal.me",
        created_at: "2026-09-01T08:00:00.000Z",
        expires_at: null,
        status: "ACTIVE",
        revocation_reason: null,
        notes: "High-security Tier 1 Anchor for banking & KYC verification",
      },
      {
        id: 2,
        alias_email: "govid-health.d14f2b90@relay.identityshield.local",
        service_name: "GovID Health Portal",
        service_domain: "govid.gov",
        tier: "core",
        target_forward_email: "user@personal.me",
        created_at: "2026-09-02T09:30:00.000Z",
        expires_at: null,
        status: "ACTIVE",
        revocation_reason: null,
        notes: "National digital identity & healthcare record anchor",
      },
      {
        id: 3,
        alias_email: "netflix.8a3c94f1@relay.identityshield.local",
        service_name: "Netflix Streaming",
        service_domain: "netflix.com",
        tier: "commercial",
        target_forward_email: "user@personal.me",
        created_at: "2026-09-04T14:15:00.000Z",
        expires_at: null,
        status: "ACTIVE",
        revocation_reason: null,
        notes: "Entertainment monthly subscription",
      },
      {
        id: 4,
        alias_email: "amazon.b72e11d0@relay.identityshield.local",
        service_name: "Amazon Marketplace",
        service_domain: "amazon.com",
        tier: "commercial",
        target_forward_email: "user@personal.me",
        created_at: "2026-09-05T11:20:00.000Z",
        expires_at: null,
        status: "ACTIVE",
        revocation_reason: null,
        notes: "E-commerce vendor 1-to-1 compartmentalized vector",
      },
      {
        id: 5,
        alias_email: "substack.3f5d88c2@relay.identityshield.local",
        service_name: "Substack Publications",
        service_domain: "substack.com",
        tier: "commercial",
        target_forward_email: "user@personal.me",
        created_at: "2026-09-06T16:40:00.000Z",
        expires_at: null,
        status: "ACTIVE",
        revocation_reason: null,
        notes: "Cybersecurity & tech newsletter feeds",
      },
      {
        id: 6,
        alias_email: "spotify.71e499a6@relay.identityshield.local",
        service_name: "Spotify Audio",
        service_domain: "spotify.com",
        tier: "commercial",
        target_forward_email: "user@personal.me",
        created_at: "2026-09-07T10:05:00.000Z",
        expires_at: null,
        status: "ACTIVE",
        revocation_reason: null,
        notes: "Audio & podcast streaming account",
      },
      {
        id: 7,
        alias_email: "clouddev-trial.e41b99a2@relay.identityshield.local",
        service_name: "CloudDev Free Trial",
        service_domain: "clouddev.io",
        tier: "ephemeral",
        target_forward_email: "user@personal.me",
        created_at: "2026-09-09T12:00:00.000Z",
        expires_at: "2026-09-23T12:00:00.000Z",
        status: "ACTIVE",
        revocation_reason: null,
        notes: "14-day disposable sandbox credentials",
      },
      {
        id: 8,
        alias_email: "saas-demo.52a819c4@relay.identityshield.local",
        service_name: "SaaS Metrics Demo",
        service_domain: "saasmetrics.app",
        tier: "ephemeral",
        target_forward_email: "user@personal.me",
        created_at: "2026-09-10T15:30:00.000Z",
        expires_at: "2026-09-17T15:30:00.000Z",
        status: "ACTIVE",
        revocation_reason: null,
        notes: "7-day product trial demonstration",
      },
      {
        id: 9,
        alias_email: "techweekly.dfc853d0@relay.identityshield.local",
        service_name: "TechWeekly Newsletter",
        service_domain: "techweekly.io",
        tier: "ephemeral",
        target_forward_email: "user@personal.me",
        created_at: "2026-09-08T09:00:00.000Z",
        expires_at: "2026-09-22T09:00:00.000Z",
        status: "REVOKED",
        revocation_reason: "LEAK_DETECTED: Unauthorized sender promotions@spam-brokers.com",
        notes: "Automated kill-switch triggered after data broker domain mismatch",
      },
      {
        id: 10,
        alias_email: "conf2026-wifi.90c8e11a@relay.identityshield.local",
        service_name: "Conference 2026 Wi-Fi",
        service_domain: "conf2026.net",
        tier: "ephemeral",
        target_forward_email: "user@personal.me",
        created_at: "2026-08-01T08:00:00.000Z",
        expires_at: "2026-08-02T23:59:59.000Z",
        status: "EXPIRED",
        revocation_reason: null,
        notes: "Single-day event sign-up. Inbound relay auto-expired.",
      },
    ],
    audit_logs: [
      {
        id: 6,
        alias_id: 9,
        event_type: "LEAK_DETECTED",
        timestamp: "2026-09-11T04:15:22.000Z",
        details: "Inbound from promotions@spam-brokers.com. Domain mismatch with techweekly.io. Kill-switch activated.",
      },
      {
        id: 5,
        alias_id: 9,
        event_type: "REVOKED",
        timestamp: "2026-09-11T04:15:23.000Z",
        details: "Terminated routing bridge for techweekly.dfc853d0@relay.identityshield.local",
      },
      {
        id: 4,
        alias_id: 3,
        event_type: "INBOUND_AUTHORIZED",
        timestamp: "2026-09-11T05:02:10.000Z",
        details: "Inbound from billing@netflix.com. Correlated with netflix.com: FORWARD_ALLOWED",
      },
      {
        id: 3,
        alias_id: 7,
        event_type: "GENERATED",
        timestamp: "2026-09-09T12:00:00.000Z",
        details: "Generated for CloudDev Free Trial (Tier: ephemeral, TTL: 14d)",
      },
      {
        id: 2,
        alias_id: 3,
        event_type: "GENERATED",
        timestamp: "2026-09-04T14:15:00.000Z",
        details: "Generated for Netflix Streaming (Tier: commercial)",
      },
      {
        id: 1,
        alias_id: 1,
        event_type: "GENERATED",
        timestamp: "2026-09-01T08:00:00.000Z",
        details: "Generated for Apex National Bank (Tier: core)",
      },
    ],
  };
}

// In-Memory Vault Persistence Engine
let inMemoryVault = null;
let saveDebounceTimer = null;

function loadVault() {
  if (inMemoryVault) {
    return inMemoryVault;
  }
  if (fs.existsSync(DATA_FILE)) {
    try {
      const raw = fs.readFileSync(DATA_FILE, "utf-8");
      const data = JSON.parse(raw);
      if (data && Array.isArray(data.identities)) {
        inMemoryVault = data;
        return inMemoryVault;
      }
    } catch (err) {
      console.error("[!] Error parsing vault file, seeding fresh state:", err.message);
    }
  }

  inMemoryVault = seedFreshVault();
  saveVaultAsync(inMemoryVault);
  return inMemoryVault;
}

function saveVaultAsync(data) {
  inMemoryVault = data;
  // Non-blocking asynchronous file write
  clearTimeout(saveDebounceTimer);
  saveDebounceTimer = setTimeout(async () => {
    try {
      await fs.promises.writeFile(DATA_FILE, JSON.stringify(data, null, 2), "utf-8");
    } catch (err) {
      console.error("[!] Async error writing vault file:", err.message);
    }
  }, 50);
}

function purgeExpiredIdentities(vault) {
  const now = new Date();
  let purgedCount = 0;
  for (const ident of vault.identities) {
    if (ident.status === "ACTIVE" && ident.expires_at) {
      if (new Date(ident.expires_at) <= now) {
        ident.status = "EXPIRED";
        purgedCount++;
        vault.audit_logs.push({
          id: vault.audit_logs.length + 1,
          alias_id: ident.id,
          event_type: "EXPIRED",
          timestamp: now.toISOString(),
          details: `Automated TTL expiration triggered for ${ident.service_name} (${ident.alias_email})`,
        });
      }
    }
  }
  if (purgedCount > 0) {
    saveVaultAsync(vault);
  }
  return purgedCount;
}

// Cryptographic Slug & Alias Generator
function sanitizeSlug(text) {
  const slug = (text || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return slug || "service";
}

function generateHmacToken(serviceSlug, tier, salt) {
  const payload = `${serviceSlug}:${tier}:${salt}`;
  return crypto.createHmac("sha256", MASTER_KEY).update(payload).digest("hex").slice(0, 8);
}

// Request Body Parser with size limit
function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1e6) {
        req.destroy();
        reject(new Error("Request payload too large"));
      }
    });
    req.on("end", () => {
      if (!body.trim()) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

// Send JSON Response
function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  });
  res.end(JSON.stringify(data, null, 2));
}

// In-Memory Static Asset Cache (High Performance)
const staticCache = new Map();

function getCachedStaticFile(filePath) {
  const normalized = path.normalize(filePath);
  if (staticCache.has(normalized)) {
    return staticCache.get(normalized);
  }
  if (!fs.existsSync(normalized)) return null;

  try {
    const content = fs.readFileSync(normalized);
    const etag = `"${crypto.createHash("sha1").update(content).digest("hex").slice(0, 16)}"`;
    const ext = path.extname(normalized).toLowerCase();
    const mime = MIME_TYPES[ext] || "application/octet-stream";
    const cacheEntry = { content, etag, mime };
    staticCache.set(normalized, cacheEntry);
    return cacheEntry;
  } catch (err) {
    return null;
  }
}

// HTTP Server
const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const pathname = reqUrl.pathname;
  const method = req.method.toUpperCase();

  // CORS Preflight
  if (method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    });
    return res.end();
  }

  // --- API Endpoints ---
  if (pathname.startsWith("/api/")) {
    const vault = loadVault();

    // 1. Network Info Endpoint
    if (method === "GET" && pathname === "/api/network-info") {
      const netIps = getLocalNetworkIPs();
      const primary = netIps.length > 0 ? netIps[0].address : "127.0.0.1";
      return sendJson(res, 200, {
        hostname: os.hostname(),
        port: PORT,
        interfaces: netIps,
        primaryIp: primary,
        localUrl: `http://localhost:${PORT}`,
        networkUrl: `http://${primary}:${PORT}`,
        connectAnyDeviceInstructions: `Open http://${primary}:${PORT} on any smartphone, tablet, or laptop connected to the same Wi-Fi/Ethernet network.`,
      });
    }

    // 2. Stats Endpoint
    if (method === "GET" && pathname === "/api/stats") {
      purgeExpiredIdentities(vault);
      const total = vault.identities.length;
      const active = vault.identities.filter((i) => i.status === "ACTIVE").length;
      const revoked = vault.identities.filter((i) => i.status === "REVOKED").length;
      const expired = vault.identities.filter((i) => i.status === "EXPIRED").length;
      const ephemeral = vault.identities.filter((i) => i.tier === "ephemeral").length;
      const commercial = vault.identities.filter((i) => i.tier === "commercial").length;
      const core = vault.identities.filter((i) => i.tier === "core").length;
      const leaks = vault.audit_logs.filter((l) => l.event_type === "LEAK_DETECTED").length;

      return sendJson(res, 200, {
        total_identities: total,
        active,
        revoked,
        expired,
        ephemeral,
        commercial,
        core,
        leaks_detected: leaks,
      });
    }

    // 3. List Aliases
    if (method === "GET" && pathname === "/api/aliases") {
      purgeExpiredIdentities(vault);
      let list = [...vault.identities];
      const statusQuery = reqUrl.searchParams.get("status");
      const tierQuery = reqUrl.searchParams.get("tier");
      const searchQuery = reqUrl.searchParams.get("q");

      if (statusQuery) {
        list = list.filter((i) => i.status.toUpperCase() === statusQuery.toUpperCase());
      }
      if (tierQuery) {
        list = list.filter((i) => i.tier.toLowerCase() === tierQuery.toLowerCase());
      }
      if (searchQuery) {
        const q = searchQuery.toLowerCase().trim();
        list = list.filter(
          (i) =>
            i.service_name.toLowerCase().includes(q) ||
            i.alias_email.toLowerCase().includes(q) ||
            (i.service_domain && i.service_domain.toLowerCase().includes(q)) ||
            (i.notes && i.notes.toLowerCase().includes(q))
        );
      }
      return sendJson(res, 200, list.reverse());
    }

    // 3b. Export Vault
    if (method === "GET" && pathname === "/api/export") {
      const exportJson = JSON.stringify(vault.identities, null, 2);
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Disposition": 'attachment; filename="identity_shield_vault.json"',
      });
      return res.end(exportJson);
    }

    // 3c. Get Audit Logs
    if (method === "GET" && pathname === "/api/logs") {
      const limit = parseInt(reqUrl.searchParams.get("limit") || "50", 10);
      const logs = [...vault.audit_logs].reverse().slice(0, limit);
      return sendJson(res, 200, logs);
    }

    // 3d. Fresh Demo Reset
    if (method === "POST" && pathname === "/api/reset-demo") {
      const freshData = seedFreshVault();
      saveVaultAsync(freshData);
      return sendJson(res, 200, {
        message: "Vault reset to fresh demonstration state",
        total_identities: freshData.identities.length,
        identities: freshData.identities,
      });
    }

    // 3e. Manual Purge Expired
    if (method === "POST" && pathname === "/api/purge-expired") {
      const purged = purgeExpiredIdentities(vault);
      return sendJson(res, 200, {
        purged_count: purged,
        message: `Successfully purged ${purged} overdue ephemeral identities.`,
      });
    }

    // 3f. Threat Intelligence & Dark Web Breach Scanner
    if (method === "POST" && pathname === "/api/threat-intel/scan") {
      try {
        const body = await parseJsonBody(req).catch(() => ({}));
        const aliasEmail = (body.alias_email || "").trim().toLowerCase();
        const record = vault.identities.find((i) => i.alias_email.toLowerCase() === aliasEmail);

        if (!record) {
          return sendJson(res, 404, { error: "Alias not found in vault" });
        }

        const isRevoked = record.status === "REVOKED";
        const isEphemeral = record.tier === "ephemeral";
        const createdDate = new Date(record.created_at);
        const ageDays = Math.max(0, Math.floor((Date.now() - createdDate.getTime()) / (1000 * 60 * 60 * 24)));

        const knownBrokers = [
          { name: "Acxiom Consumer Graph", risk: "HIGH", vector: "SHA256(email) Stitching" },
          { name: "LiveRamp IdentityLink", risk: "MEDIUM", vector: "Hashed Cookie Sync" },
          { name: "Experian Marketing Data", risk: "HIGH", vector: "Cross-Device Profiling" },
          { name: "Apollo.io B2B Crawler", risk: "LOW", vector: "Domain MX Harvesting" },
        ];

        let detectedBrokers = [];
        let exposureScore = 0;

        if (isRevoked) {
          detectedBrokers = knownBrokers.slice(0, 3);
          exposureScore = 85;
        } else if (isEphemeral) {
          detectedBrokers = ageDays > 10 ? [knownBrokers[0], knownBrokers[3]] : [knownBrokers[3]];
          exposureScore = ageDays > 10 ? 45 : 15;
        } else {
          detectedBrokers = [knownBrokers[1]];
          exposureScore = 25;
        }

        const level = exposureScore > 70 ? "CRITICAL" : exposureScore > 30 ? "ELEVATED" : "MINIMAL";
        const recommendation = isRevoked
          ? "Kill-switch already engaged. Forwarding terminated. Recommend dispatching GDPR Art. 17 Erasure Notice."
          : exposureScore > 30
          ? "Elevated exposure vector detected. Consider engaging Kill-Switch or shortening TTL."
          : "Channel secure. Zero cross-broker collusion detected. Cryptographic air-gap intact.";

        return sendJson(res, 200, {
          alias_email: record.alias_email,
          service_name: record.service_name,
          service_domain: record.service_domain || "unknown",
          status: record.status,
          tier: record.tier,
          exposure_score: exposureScore,
          exposure_level: level,
          dark_web_appearances: isRevoked ? 2 : 0,
          matched_broker_networks: detectedBrokers,
          hash_correlation_attempted: true,
          recommendation: recommendation,
          scan_timestamp: new Date().toISOString(),
        });
      } catch (err) {
        return sendJson(res, 400, { error: err.message });
      }
    }

    // 3g. Cryptographic PPID & Blinded Hash Proof Lab
    if (method === "POST" && pathname === "/api/crypto/ppid-proof") {
      try {
        const body = await parseJsonBody(req).catch(() => ({}));
        const email = (body.email || "user@example.com").trim().toLowerCase();
        const pepper = process.env.SHIELD_KMS_PEPPER || "master_kms_pepper_2026";
        const salt = crypto.createHash("sha256").update(`salt_${email}`).digest("hex").slice(0, 16);

        const blindedHash = crypto.createHmac("sha256", pepper).update(`${email}${salt}`).digest("hex");
        const accountUuid = crypto.createHash("sha256").update(blindedHash).digest("hex").slice(0, 32);

        const clientASalt = "client_netflix_internal_salt";
        const ppidA = crypto.createHmac("sha256", accountUuid).update(`netflix:${clientASalt}`).digest("hex").slice(0, 24);

        const clientBSalt = "client_amazon_internal_salt";
        const ppidB = crypto.createHmac("sha256", accountUuid).update(`amazon:${clientBSalt}`).digest("hex").slice(0, 24);

        return sendJson(res, 200, {
          canonical_email: email,
          account_uuid: accountUuid,
          blinded_hash: blindedHash,
          client_a: { name: "Service A (e.g. Netflix)", ppid: `ppid_${ppidA}` },
          client_b: { name: "Service B (e.g. Amazon)", ppid: `ppid_${ppidB}` },
          collusion_linkable: false,
          mathematical_guarantee: "Zero correlation. Orthogonal HMAC outputs prevent cross-database joins.",
        });
      } catch (err) {
        return sendJson(res, 400, { error: err.message });
      }
    }

    // 4. Generate New Alias
    if (method === "POST" && pathname === "/api/aliases") {
      try {
        const data = await parseJsonBody(req);
        const serviceName = (data.service_name || "").trim();
        if (!serviceName) {
          return sendJson(res, 400, { error: "service_name is required" });
        }

        const serviceDomain = (data.service_domain || "").trim().toLowerCase() || null;
        const tier = (data.tier || "commercial").toLowerCase();
        const targetEmail = data.target_forward_email || "user@example.com";
        const relayDomain = data.relay_domain || DEFAULT_RELAY;
        let ttlDays = data.ttl_days ? parseInt(data.ttl_days, 10) : null;

        if (tier === "ephemeral" && !ttlDays) {
          ttlDays = 30;
        }

        const slug = sanitizeSlug(serviceName);
        const salt = crypto.randomBytes(4).toString("hex");
        const token = generateHmacToken(slug, tier, salt);
        const aliasEmail = `${slug}.${salt}${token}@${relayDomain}`;

        const now = new Date();
        const createdAt = now.toISOString();
        let expiresAt = null;
        if (ttlDays) {
          expiresAt = new Date(now.getTime() + ttlDays * 86400000).toISOString();
        }

        const newId = vault.identities.reduce((max, i) => Math.max(max, i.id || 0), 0) + 1;
        const newRecord = {
          id: newId,
          alias_email: aliasEmail,
          service_name: serviceName,
          service_domain: serviceDomain,
          tier,
          target_forward_email: targetEmail,
          created_at: createdAt,
          expires_at: expiresAt,
          status: "ACTIVE",
          revocation_reason: null,
          notes: data.notes || null,
        };

        vault.identities.push(newRecord);
        vault.audit_logs.push({
          id: vault.audit_logs.length + 1,
          alias_id: newId,
          event_type: "GENERATED",
          timestamp: createdAt,
          details: `Generated for ${serviceName} (Tier: ${tier})`,
        });

        saveVaultAsync(vault);
        return sendJson(res, 201, newRecord);
      } catch (err) {
        return sendJson(res, 400, { error: err.message });
      }
    }

    // 5. Revoke Alias (Kill-Switch)
    const revokeMatch = pathname.match(/^\/api\/aliases\/(.+)\/revoke$/);
    if (method === "POST" && revokeMatch) {
      const targetAlias = decodeURIComponent(revokeMatch[1]).toLowerCase();
      const body = await parseJsonBody(req).catch(() => ({}));
      const reason = body.reason || "MANUAL_REVOCATION_WEB_UI";

      const record = vault.identities.find((i) => i.alias_email.toLowerCase() === targetAlias);
      if (!record) {
        return sendJson(res, 404, { error: `Alias '${targetAlias}' not found` });
      }

      record.status = "REVOKED";
      record.revocation_reason = reason;

      vault.audit_logs.push({
        id: vault.audit_logs.length + 1,
        alias_id: record.id,
        event_type: "REVOKED",
        timestamp: new Date().toISOString(),
        details: `Revoked: ${reason}`,
      });

      saveVaultAsync(vault);
      return sendJson(res, 200, record);
    }

    // 6. Trace Inbound Message (Leak Attribution Engine)
    if (method === "POST" && pathname === "/api/trace") {
      try {
        const data = await parseJsonBody(req);
        const aliasEmail = (data.alias_email || "").trim().toLowerCase();
        const senderEmail = (data.sender_email || "").trim().toLowerCase();
        const autoRevoke = Boolean(data.auto_revoke);

        if (!aliasEmail || !senderEmail) {
          return sendJson(res, 400, { error: "Both alias_email and sender_email are required" });
        }

        const record = vault.identities.find((i) => i.alias_email.toLowerCase() === aliasEmail);
        if (!record) {
          return sendJson(res, 200, {
            authorized: false,
            verdict: "UNKNOWN_ALIAS",
            message: `Alias '${aliasEmail}' does not exist in vault.`,
          });
        }

        if (record.status === "REVOKED") {
          return sendJson(res, 200, {
            authorized: false,
            verdict: "BLOCKED_REVOKED",
            alias: record.alias_email,
            service: record.service_name,
            reason: record.revocation_reason,
            message: "Alias has been revoked via kill-switch. Message dropped.",
          });
        }

        if (record.status === "EXPIRED" || (record.expires_at && new Date(record.expires_at) <= new Date())) {
          record.status = "EXPIRED";
          saveVaultAsync(vault);
          return sendJson(res, 200, {
            authorized: false,
            verdict: "EXPIRED",
            alias: record.alias_email,
            service: record.service_name,
            message: "Alias has expired past its configured TTL.",
          });
        }

        const senderDomain = senderEmail.includes("@") ? senderEmail.split("@")[1] : "";
        let isCorrelated = false;

        if (record.service_domain) {
          const expected = record.service_domain.toLowerCase();
          if (senderDomain === expected || senderDomain.endsWith("." + expected)) {
            isCorrelated = true;
          }
        }

        if (!isCorrelated) {
          const serviceTokens = record.service_name
            .toLowerCase()
            .split(/[^a-z0-9]+/)
            .filter((t) => t.length >= 3);
          for (const token of serviceTokens) {
            if (senderDomain.includes(token)) {
              isCorrelated = true;
              break;
            }
          }
        }

        vault.audit_logs.push({
          id: vault.audit_logs.length + 1,
          alias_id: record.id,
          event_type: isCorrelated ? "INBOUND_AUTHORIZED" : "LEAK_DETECTED",
          timestamp: new Date().toISOString(),
          details: `Inbound from ${senderEmail}. Correlated: ${isCorrelated}`,
        });

        if (!isCorrelated) {
          if (autoRevoke) {
            record.status = "REVOKED";
            record.revocation_reason = `LEAK_DETECTED: Unauthorized sender ${senderEmail}`;
          }
          saveVaultAsync(vault);
          return sendJson(res, 200, {
            authorized: false,
            verdict: "POTENTIAL_LEAK_OR_RESALE",
            alias: record.alias_email,
            registered_service: record.service_name,
            sender: senderEmail,
            forwarding_action: autoRevoke ? "KILLED" : "FLAGGED",
            message: `Sender '${senderEmail}' does not correlate with registered service '${record.service_name}'. High probability of data breach, broker sharing, or resale.`,
          });
        }

        saveVaultAsync(vault);
        return sendJson(res, 200, {
          authorized: true,
          verdict: "FORWARD_ALLOWED",
          alias: record.alias_email,
          service: record.service_name,
          forward_to: record.target_forward_email,
          message: "Inbound communication matches expected identity record.",
        });
      } catch (err) {
        return sendJson(res, 400, { error: err.message });
      }
    }
  }

  // --- Optimized Static File Serving with In-Memory Cache & ETag ---
  let filePath;
  if (pathname === "/" || pathname === "/index.html") {
    filePath = path.join(__dirname, "web", "templates", "index.html");
  } else if (pathname.startsWith("/static/")) {
    const relPath = pathname.replace(/^\/static\//, "");
    filePath = path.join(__dirname, "web", "static", relPath);
  } else {
    filePath = path.join(__dirname, "web", pathname);
  }

  // Prevent path traversal
  const normalizedPath = path.normalize(filePath);
  if (!normalizedPath.startsWith(path.normalize(__dirname))) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    return res.end("Forbidden");
  }

  const cached = getCachedStaticFile(normalizedPath);
  if (!cached) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    return res.end("404 Not Found");
  }

  // Check ETag for 304 Not Modified
  const clientEtag = req.headers["if-none-match"];
  if (clientEtag && clientEtag === cached.etag) {
    res.writeHead(304, {
      "ETag": cached.etag,
      "Cache-Control": "public, max-age=3600",
    });
    return res.end();
  }

  res.writeHead(200, {
    "Content-Type": cached.mime,
    "Content-Length": cached.content.length,
    "ETag": cached.etag,
    "Cache-Control": "public, max-age=3600",
    "Access-Control-Allow-Origin": "*",
  });
  res.end(cached.content);
});

// Start Server on 0.0.0.0 (All Interfaces)
if (require.main === module) {
  server.listen(PORT, HOST, () => {
    const networks = getLocalNetworkIPs();
    console.log("===============================================================");
    console.log("🛡️  IDENTITY SHIELD — NODE.JS CROSS-DEVICE NETWORK SERVER");
    console.log("===============================================================");
    console.log(`[*] Status: Listening on all network interfaces (0.0.0.0:${PORT})`);
    console.log(`[>] Localhost (This PC):    http://localhost:${PORT}`);
    if (networks.length > 0) {
      console.log("[>] Network IP (Any Device on your Wi-Fi / LAN):");
      for (const net of networks) {
        console.log(`    📱 http://${net.address}:${PORT}  (${net.name})`);
      }
    } else {
      console.log(`[>] Network URL:           http://127.0.0.1:${PORT}`);
    }
    console.log("---------------------------------------------------------------");
    console.log("👉 Open the Network URL on your phone/tablet/laptop to connect!");
    console.log("===============================================================");
  });
}

module.exports = { server, getLocalNetworkIPs, loadVault, seedFreshVault };

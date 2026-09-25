// ScamRatio Backend
// server.js

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const path = require("path");
const dns = require("dns").promises;
const net = require("net");
const tls = require("tls");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.RENDER ? { rejectUnauthorized: false } : false
    })
  : null;

const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

let databaseReady = false;

// --------------------------------------------------
// Middleware
// --------------------------------------------------

app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

const allowedOrigins = new Set([
  "https://muhammadumar4412667.github.io",
  "https://scam-ratio.onrender.com",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5500",
  "http://127.0.0.1:5500"
]);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.has(origin)) return callback(null, true);
      return callback(new Error("Origin is not allowed by ScamRatio API."));
    },
    credentials: true
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// --------------------------------------------------
// Website checker helpers
// --------------------------------------------------

function normalizeUrl(input) {
  if (!input || typeof input !== "string") return null;

  let value = input.trim();
  if (!value) return null;

  if (!/^https?:\/\//i.test(value)) {
    value = `https://${value}`;
  }

  try {
    const url = new URL(value);

    if (!["http:", "https:"].includes(url.protocol)) {
      return null;
    }

    return url;
  } catch {
    return null;
  }
}

function isPrivateIp(ip) {
  if (!ip) return false;

  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);

    return (
      parts[0] === 10 ||
      parts[0] === 127 ||
      (parts[0] === 169 && parts[1] === 254) ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
    );
  }

  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();

    return (
      normalized === "::1" ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      normalized.startsWith("fe80:")
    );
  }

  return false;
}

function getRootDomain(hostname) {
  const parts = hostname.toLowerCase().split(".").filter(Boolean);

  if (parts.length <= 2) {
    return parts.join(".");
  }

  const secondLevelTlds = new Set([
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.nz",
    "com.br",
    "com.cn",
    "com.pk",
    "co.jp",
    "co.in"
  ]);

  const lastTwo = parts.slice(-2).join(".");

  return secondLevelTlds.has(lastTwo)
    ? parts.slice(-3).join(".")
    : parts.slice(-2).join(".");
}

function analyzeDomain(url) {
  const hostname = url.hostname.toLowerCase();
  const fullUrl = url.toString().toLowerCase();

  let riskScore = 0;
  const warnings = [];
  const positives = [];

  if (url.protocol === "https:") {
    positives.push({
      type: "security",
      message: "Website uses HTTPS encryption."
    });
  } else {
    riskScore += 20;

    warnings.push({
      type: "security",
      message: "Website does not use HTTPS."
    });
  }

  if (net.isIP(hostname)) {
    riskScore += 30;

    warnings.push({
      type: "domain",
      message: "The website uses an IP address instead of a normal domain."
    });
  }

  if (hostname.includes("@")) {
    riskScore += 20;

    warnings.push({
      type: "domain",
      message: "The URL contains an unusual @ character."
    });
  }

  if (hostname.length > 50) {
    riskScore += 10;

    warnings.push({
      type: "domain",
      message: "The domain name is unusually long."
    });
  }

  const parts = hostname.split(".");

  if (parts.length >= 5) {
    riskScore += 10;

    warnings.push({
      type: "domain",
      message: "The domain contains an unusually large number of subdomains."
    });
  }

  const suspiciousKeywords = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "wallet",
    "payment",
    "invoice",
    "bonus",
    "gift",
    "free",
    "claim",
    "recover",
    "unlock",
    "support"
  ];

  const keywordMatches = suspiciousKeywords.filter((keyword) =>
    hostname.includes(keyword)
  );

  if (keywordMatches.length >= 2) {
    riskScore += 15;

    warnings.push({
      type: "domain",
      message:
        "The domain contains multiple words commonly associated with account or payment activity."
    });
  }

  if (hostname.includes("xn--")) {
    riskScore += 15;

    warnings.push({
      type: "domain",
      message:
        "The domain uses Punycode, which can sometimes be associated with look-alike domains."
    });
  }

  const hyphenCount = (hostname.match(/-/g) || []).length;

  if (hyphenCount >= 3) {
    riskScore += 8;

    warnings.push({
      type: "domain",
      message: "The domain contains several hyphens."
    });
  }

  const digitCount = (hostname.match(/\d/g) || []).length;

  if (digitCount >= 4) {
    riskScore += 8;

    warnings.push({
      type: "domain",
      message: "The domain contains an unusually high number of digits."
    });
  }

  if (url.username || url.password) {
    riskScore += 25;

    warnings.push({
      type: "url",
      message: "The URL contains embedded username or password information."
    });
  }

  const suspiciousPathWords = [
    "login",
    "signin",
    "verify",
    "verification",
    "password",
    "reset",
    "wallet",
    "payment",
    "invoice",
    "recover",
    "unlock"
  ];

  const pathMatches = suspiciousPathWords.filter((word) =>
    url.pathname.toLowerCase().includes(word)
  );

  if (pathMatches.length >= 2) {
    riskScore += 10;

    warnings.push({
      type: "url",
      message:
        "The URL path contains multiple account, verification, or payment-related terms."
    });
  }

  if (fullUrl.length > 200) {
    riskScore += 10;

    warnings.push({
      type: "url",
      message: "The URL is unusually long."
    });
  }

  if (!warnings.length) {
    positives.push({
      type: "domain",
      message: "No obvious suspicious URL structure was detected."
    });
  }

  return {
    riskScore: Math.min(riskScore, 100),
    warnings,
    positives
  };
}

async function checkDns(hostname) {
  const result = {
    available: false,
    addresses: [],
    ipv4: [],
    ipv6: [],
    mx: [],
    nameservers: [],
    txt: [],
    privateIpDetected: false,
    error: null
  };

  try {
    const records = await dns.lookup(hostname, {
      all: true,
      verbatim: true
    });

    result.addresses = records.map((record) => record.address);

    result.ipv4 = records
      .filter((record) => record.family === 4)
      .map((record) => record.address);

    result.ipv6 = records
      .filter((record) => record.family === 6)
      .map((record) => record.address);

    result.privateIpDetected = result.addresses.some(isPrivateIp);
    result.available = result.addresses.length > 0;
  } catch (error) {
    result.error = error.message;
  }

  try {
    result.mx = (await dns.resolveMx(hostname))
      .sort((a, b) => a.priority - b.priority)
      .map((record) => ({
        exchange: record.exchange,
        priority: record.priority
      }));
  } catch {
    result.mx = [];
  }

  try {
    result.nameservers = await dns.resolveNs(hostname);
  } catch {
    result.nameservers = [];
  }

  try {
    result.txt = (await dns.resolveTxt(hostname)).map((record) =>
      record.join("")
    );
  } catch {
    result.txt = [];
  }

  return result;
}

async function checkSsl(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 8000
      },
      () => {
        try {
          const certificate = socket.getPeerCertificate();

          const authorized = socket.authorized;
          const authorizationError = socket.authorizationError || null;

          let validFrom = null;
          let validTo = null;
          let daysRemaining = null;

          if (certificate && certificate.valid_from) {
            validFrom = certificate.valid_from;
          }

          if (certificate && certificate.valid_to) {
            validTo = certificate.valid_to;

            const expiryTime = new Date(certificate.valid_to).getTime();

            daysRemaining = Math.floor(
              (expiryTime - Date.now()) / 86400000
            );
          }

          resolve({
            available: true,
            valid: authorized,
            authorized,
            authorizationError,
            subject: certificate.subject || null,
            issuer: certificate.issuer || null,
            validFrom,
            validTo,
            daysRemaining
          });
        } catch (error) {
          resolve({
            available: false,
            valid: false,
            error: error.message
          });
        } finally {
          socket.end();
        }
      }
    );

    socket.on("error", (error) => {
      resolve({
        available: false,
        valid: false,
        error: error.message
      });
    });

    socket.on("timeout", () => {
      socket.destroy();

      resolve({
        available: false,
        valid: false,
        error: "SSL connection timed out."
      });
    });
  });
}

async function checkDomainIntelligence(hostname) {
  const rootDomain = getRootDomain(hostname);

  const result = {
    available: false,
    root: rootDomain,
    registrar: null,
    created: null,
    expires: null,
    ageDays: null,
    daysUntilExpiry: null,
    status: [],
    nameservers: [],
    dnssec: null,
    error: null
  };

  if (!rootDomain || net.isIP(rootDomain)) {
    result.error = "RDAP lookup is not available for IP addresses.";
    return result;
  }

  try {
    const response = await fetch(
      "https://rdap.verisign.com/com/v1/domain/" +
        encodeURIComponent(rootDomain),
      {
        headers: {
          Accept: "application/rdap+json, application/json"
        },
        signal: AbortSignal.timeout(10000)
      }
    );

    if (!response.ok) {
      throw new Error(`RDAP returned HTTP ${response.status}`);
    }

    const data = await response.json();

    result.available = true;

    if (Array.isArray(data.entities)) {
      const registrarEntity = data.entities.find(
        (entity) =>
          Array.isArray(entity.roles) &&
          entity.roles.includes("registrar")
      );

      if (registrarEntity) {
        const vcard = registrarEntity.vcardArray;

        if (
          Array.isArray(vcard) &&
          Array.isArray(vcard[1])
        ) {
          const fn = vcard[1].find(
            (item) => Array.isArray(item) && item[0] === "fn"
          );

          if (fn && fn[3]) {
            result.registrar = fn[3];
          }
        }
      }
    }

    if (Array.isArray(data.events)) {
      const registrationEvent = data.events.find(
        (event) =>
          event.eventAction === "registration" ||
          event.eventAction === "registered"
      );

      const expirationEvent = data.events.find(
        (event) =>
          event.eventAction === "expiration" ||
          event.eventAction === "expiry"
      );

      if (registrationEvent && registrationEvent.eventDate) {
        result.created = registrationEvent.eventDate;

        const createdTime = new Date(
          registrationEvent.eventDate
        ).getTime();

        if (!Number.isNaN(createdTime)) {
          result.ageDays = Math.max(
            0,
            Math.floor(
              (Date.now() - createdTime) / 86400000
            )
          );
        }
      }

      if (expirationEvent && expirationEvent.eventDate) {
        result.expires = expirationEvent.eventDate;

        const expiryTime = new Date(
          expirationEvent.eventDate
        ).getTime();

        if (!Number.isNaN(expiryTime)) {
          result.daysUntilExpiry = Math.floor(
            (expiryTime - Date.now()) / 86400000
          );
        }
      }
    }

    if (Array.isArray(data.status)) {
      result.status = data.status;
    }

    if (Array.isArray(data.nameservers)) {
      result.nameservers = data.nameservers
        .map((server) => server.ldhName || server.unicodeName)
        .filter(Boolean);
    }

    if (typeof data.secureDNS === "object") {
      result.dnssec = Boolean(
        data.secureDNS.delegationSigned
      );
    }

    return result;
  } catch (error) {
    result.error = error.message;
    return result;
  }
}

async function checkVirusTotal(domain) {
  const result = {
    available: false,
    malicious: 0,
    suspicious: 0,
    harmless: 0,
    undetected: 0,
    timeout: 0,
    reputation: null,
    lastAnalysisDate: null,
    error: null
  };

  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey) {
    result.error = "VirusTotal API key is not configured.";
    return result;
  }

  if (!domain || net.isIP(domain)) {
    result.error =
      "VirusTotal domain lookup requires a domain name.";
    return result;
  }

  try {
    const response = await fetch(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(
        domain
      )}`,
      {
        headers: {
          "x-apikey": apiKey,
          Accept: "application/json"
        },
        signal: AbortSignal.timeout(12000)
      }
    );

    if (!response.ok) {
      throw new Error(
        `VirusTotal returned HTTP ${response.status}`
      );
    }

    const data = await response.json();

    const attributes =
      data?.data?.attributes || {};

    const stats =
      attributes.last_analysis_stats || {};

    result.available = true;
    result.malicious = Number(
      stats.malicious || 0
    );

    result.suspicious = Number(
      stats.suspicious || 0
    );

    result.harmless = Number(
      stats.harmless || 0
    );

    result.undetected = Number(
      stats.undetected || 0
    );

    result.timeout = Number(
      stats.timeout || 0
    );

    if (
      typeof attributes.reputation === "number"
    ) {
      result.reputation =
        attributes.reputation;
    }

    if (attributes.last_analysis_date) {
      result.lastAnalysisDate =
        new Date(
          attributes.last_analysis_date * 1000
        ).toISOString();
    }

    return result;
  } catch (error) {
    result.error = error.message;
    return result;
  }
}

function analyzeVirusTotal(virusTotal) {
  let riskScore = 0;

  const warnings = [];
  const positives = [];

  if (!virusTotal || !virusTotal.available) {
    return {
      riskScore,
      warnings,
      positives
    };
  }

  if (virusTotal.malicious > 0) {
    riskScore += Math.min(
      virusTotal.malicious * 12,
      60
    );

    warnings.push({
      type: "virustotal",
      message:
        `VirusTotal reports ${virusTotal.malicious} security engine(s) flagging this domain as malicious.`
    });
  }

  if (virusTotal.suspicious > 0) {
    riskScore += Math.min(
      virusTotal.suspicious * 5,
      25
    );

    warnings.push({
      type: "virustotal",
      message:
        `VirusTotal reports ${virusTotal.suspicious} security engine(s) flagging this domain as suspicious.`
    });
  }

  if (
    typeof virusTotal.reputation === "number" &&
    virusTotal.reputation < -10
  ) {
    riskScore += 15;

    warnings.push({
      type: "virustotal",
      message:
        "VirusTotal shows a negative community reputation for this domain."
    });
  }

  if (
    virusTotal.malicious === 0 &&
    virusTotal.suspicious === 0
  ) {
    positives.push({
      type: "virustotal",
      message:
        "VirusTotal reports no malicious or suspicious detections for this domain."
    });
  }

  if (
    typeof virusTotal.reputation === "number" &&
    virusTotal.reputation > 10 &&
    virusTotal.malicious === 0 &&
    virusTotal.suspicious === 0
  ) {
    positives.push({
      type: "virustotal",
      message:
        "VirusTotal shows a positive community reputation for this domain."
    });
  }

  return {
    riskScore: Math.min(riskScore, 100),
    warnings,
    positives
  };
}

function analyzeDomainIntelligence(domainInfo) {
  let riskScore = 0;

  const warnings = [];
  const positives = [];

  if (!domainInfo || !domainInfo.available) {
    return {
      riskScore,
      warnings,
      positives
    };
  }

  if (typeof domainInfo.ageDays === "number") {
    if (domainInfo.ageDays < 30) {
      riskScore += 35;

      warnings.push({
        type: "domain-age",
        message:
          "The domain appears to be less than 30 days old."
      });
    } else if (domainInfo.ageDays < 90) {
      riskScore += 20;

      warnings.push({
        type: "domain-age",
        message:
          "The domain appears to be less than 90 days old."
      });
    } else if (domainInfo.ageDays < 365) {
      riskScore += 8;

      warnings.push({
        type: "domain-age",
        message:
          "The domain is less than one year old."
      });
    } else {
      positives.push({
        type: "domain-age",
        message:
          "The domain has been registered for more than one year."
      });
    }
  }

  if (
    typeof domainInfo.daysUntilExpiry === "number"
  ) {
    if (domainInfo.daysUntilExpiry < 0) {
      riskScore += 30;

      warnings.push({
        type: "domain-expiry",
        message:
          "The domain registration appears to have expired."
      });
    } else if (
      domainInfo.daysUntilExpiry < 30
    ) {
      riskScore += 10;

      warnings.push({
        type: "domain-expiry",
        message:
          "The domain registration is due to expire within 30 days."
      });
    }
  }

  if (domainInfo.registrar) {
    positives.push({
      type: "domain",
      message:
        `Registrar information is available: ${domainInfo.registrar}.`
    });
  }

  if (
    domainInfo.nameservers &&
    domainInfo.nameservers.length
  ) {
    positives.push({
      type: "dns",
      message:
        "Domain nameserver information is available."
    });
  }

  if (domainInfo.dnssec === true) {
    positives.push({
      type: "dnssec",
      message:
        "DNSSEC is enabled for the domain."
    });
  }

  return {
    riskScore: Math.min(riskScore, 100),
    warnings,
    positives
  };
}

// --------------------------------------------------
// Overall Scam Check
// --------------------------------------------------

async function performScamCheck(input) {
  const url = normalizeUrl(input);

  if (!url) {
    throw new Error(
      "Please enter a valid website URL."
    );
  }

  const hostname =
    url.hostname.toLowerCase();

  const domainAnalysis =
    analyzeDomain(url);

  const [
    dnsResult,
    sslResult,
    domainIntelligence,
    virusTotal
  ] = await Promise.all([
    checkDns(hostname),
    checkSsl(hostname),
    checkDomainIntelligence(hostname),
    checkVirusTotal(
      getRootDomain(hostname)
    )
  ]);

  const vtAnalysis =
    analyzeVirusTotal(virusTotal);

  const domainInfoAnalysis =
    analyzeDomainIntelligence(
      domainIntelligence
    );

  let riskScore =
    domainAnalysis.riskScore;

  const warnings = [
    ...domainAnalysis.warnings
  ];

  const positives = [
    ...domainAnalysis.positives
  ];

  if (!dnsResult.available) {
    riskScore += 20;

    warnings.push({
      type: "dns",
      message:
        "DNS information could not be confirmed for this domain."
    });
  } else {
    positives.push({
      type: "dns",
      message:
        "The domain resolves through DNS."
    });
  }

  if (dnsResult.privateIpDetected) {
    riskScore += 25;

    warnings.push({
      type: "dns",
      message:
        "The domain resolved to a private or local IP address."
    });
  }

  if (url.protocol === "https:") {
    if (
      sslResult.available &&
      sslResult.valid
    ) {
      positives.push({
        type: "ssl",
        message:
          "The website has a valid SSL/TLS certificate."
      });
    } else if (
      !sslResult.available
    ) {
      riskScore += 8;

      warnings.push({
        type: "ssl",
        message:
          "HTTPS is being used, but the SSL certificate could not be fully verified."
      });
    } else {
      riskScore += 25;

      warnings.push({
        type: "ssl",
        message:
          "The SSL/TLS certificate could not be verified as valid."
      });
    }
  }

  riskScore +=
    domainInfoAnalysis.riskScore +
    vtAnalysis.riskScore;

  warnings.push(
    ...domainInfoAnalysis.warnings,
    ...vtAnalysis.warnings
  );

  positives.push(
    ...domainInfoAnalysis.positives,
    ...vtAnalysis.positives
  );

  if (virusTotal.available) {
    if (virusTotal.malicious >= 5) {
      riskScore = Math.max(
        riskScore,
        80
      );
    } else if (
      virusTotal.malicious >= 2
    ) {
      riskScore = Math.max(
        riskScore,
        70
      );
    }
  }

  riskScore = Math.max(
    0,
    Math.min(
      Math.round(riskScore),
      100
    )
  );

  let riskLevel = "Low Risk";
  let status = "safe";

  if (riskScore >= 70) {
    riskLevel = "High Risk";
    status = "danger";
  } else if (riskScore >= 40) {
    riskLevel = "Medium Risk";
    status = "warning";
  }

  const uniqueByMessage = (items) => {
    const seen = new Set();

    return items.filter((item) => {
      if (
        !item ||
        !item.message ||
        seen.has(item.message)
      ) {
        return false;
      }

      seen.add(item.message);
      return true;
    });
  };

  const finalWarnings =
    uniqueByMessage(warnings);

  const finalPositives =
    uniqueByMessage(positives);

  let summary;

  if (riskScore >= 70) {
    summary =
      "Multiple risk signals were detected. Review the warnings carefully before trusting this website.";
  } else if (riskScore >= 40) {
    summary =
      "Some risk signals were detected. Review the available website information before trusting it.";
  } else if (finalWarnings.length) {
    summary =
      "The website has a relatively low overall risk score, but some signals should still be reviewed.";
  } else {
    summary =
      "No major warning signals were detected by the checks currently available.";
  }

  const domainOldEnough =
    typeof domainIntelligence.ageDays ===
      "number" &&
    domainIntelligence.ageDays >= 730;

  const vtClean =
    virusTotal.available &&
    virusTotal.malicious === 0 &&
    virusTotal.suspicious === 0;

  const sslValid =
    url.protocol === "https:" &&
    sslResult.available &&
    sslResult.valid;

  const trusted =
    sslValid &&
    domainOldEnough &&
    vtClean;

  if (
    trusted &&
    riskScore < 5
  ) {
    riskScore = 5;
  }

  return {
    success: true,

    checkedAt:
      new Date().toISOString(),

    target: {
      input,
      url: url.toString(),
      domain: hostname
    },

    score: riskScore,

    riskLevel,

    status,

    summary,

    checks: {
      https: {
        enabled:
          url.protocol === "https:",
        valid:
          sslResult.valid
      },

      dnsAvailable:
        dnsResult.available,

      ipAddresses:
        dnsResult.addresses,

      ssl:
        sslResult,

      domainAge: {
        available:
          typeof domainIntelligence.ageDays ===
          "number",
        ageDays:
          domainIntelligence.ageDays,
        created:
          domainIntelligence.created
      },

      domainIntelligence,

      dns:
        dnsResult,

      virusTotal
    },

    warnings:
      finalWarnings.map(
        (item) => item.message
      ),

    positives:
      finalPositives.map(
        (item) => item.message
      ),

    disclaimer:
      "ScamRatio provides automated website risk signals and does not guarantee that a website is safe or fraudulent."
  };
}

// --------------------------------------------------
// Database / Authentication helpers
// --------------------------------------------------

async function initDatabase() {
  if (!pool) {
    console.log(
      "PostgreSQL is not configured. Authentication is disabled locally."
    );

    return;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reset_token_hash TEXT,
      reset_token_expires_at TIMESTAMPTZ
    );
  `);

  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS name TEXT,
      ADD COLUMN IF NOT EXISTS reset_token_hash TEXT,
      ADD COLUMN IF NOT EXISTS reset_token_expires_at TIMESTAMPTZ;
  `);

  await pool.query("SELECT 1");

  databaseReady = true;

  console.log(
    "PostgreSQL connected and users table is ready."
  );
}

function requireDatabase(res) {
  if (!pool || !databaseReady) {
    res.status(503).json({
      success: false,
      error:
        "Authentication database is not available."
    });

    return false;
  }

  return true;
}

function parseCookies(req) {
  const header = req.headers.cookie;

  if (!header) {
    return {};
  }

  return header
    .split(";")
    .reduce((out, part) => {
      const index = part.indexOf("=");

      if (index < 0) {
        return out;
      }

      const key =
        part.slice(0, index).trim();

      const value =
        part.slice(index + 1).trim();

      try {
        out[key] =
          decodeURIComponent(value);
      } catch {
        out[key] = value;
      }

      return out;
    }, {});
}

function getAuthToken(req) {
  const cookies =
    parseCookies(req);

  if (cookies.scamratio_token) {
    return cookies.scamratio_token;
  }

  const authorization =
    req.headers.authorization || "";

  if (
    authorization.startsWith("Bearer ")
  ) {
    return authorization
      .slice(7)
      .trim();
  }

  return null;
}

function getRememberMe(body) {
  const value =
    body?.rememberMe ??
    body?.remember ??
    true;

  return !(
    value === false ||
    value === "false" ||
    value === 0 ||
    value === "0"
  );
}

function getAuthCookieOptions(
  rememberMe = true
) {
  return {
    httpOnly: true,

    secure:
      Boolean(process.env.RENDER),

    sameSite:
      process.env.RENDER
        ? "none"
        : "lax",

    path: "/",

    maxAge:
      (rememberMe ? 30 : 1) *
      24 *
      60 *
      60 *
      1000
  };
}

function createAuthToken(
  userId,
  rememberMe = true
) {
  return jwt.sign(
    {
      sub: String(userId)
    },
    JWT_SECRET,
    {
      expiresIn:
        rememberMe
          ? "30d"
          : "1d"
    }
  );
}

function sanitizeUser(user) {
  return {
    id: String(user.id),

    email:
      user.email,

    name:
      user.name || "",

    createdAt:
      user.created_at
  };
}

async function getAuthenticatedUser(req) {
  if (!pool) {
    return null;
  }

  const token =
    getAuthToken(req);

  if (!token) {
    return null;
  }

  try {
    const payload =
      jwt.verify(
        token,
        JWT_SECRET
      );

    const result =
      await pool.query(
        `SELECT id, email, name, created_at
         FROM users
         WHERE id = $1
         LIMIT 1`,
        [payload.sub]
      );

    return (
      result.rows[0] ||
      null
    );
  } catch {
    return null;
  }
}

function isAllowedAuthOrigin(req) {
  const origin =
    req.headers.origin;

  return (
    !origin ||
    allowedOrigins.has(origin)
  );
}

async function sendPasswordResetEmail(
  email,
  resetUrl
) {
  const resendApiKey =
    process.env.RESEND_API_KEY;

  const fromEmail =
    process.env.AUTH_FROM_EMAIL;

  if (
    !resendApiKey ||
    !fromEmail
  ) {
    return {
      sent: false
    };
  }

  const response =
    await fetch(
      "https://api.resend.com/emails",
      {
        method: "POST",

        headers: {
          Authorization:
            `Bearer ${resendApiKey}`,

          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          from:
            fromEmail,

          to: [email],

          subject:
            "Reset your ScamRatio password",

          html: `
            <div style="font-family:Arial,sans-serif;line-height:1.6">
              <h2>ScamRatio password reset</h2>

              <p>
                We received a request to reset
                your ScamRatio password.
              </p>

              <p>
                <a href="${resetUrl}">
                  Reset your password
                </a>
              </p>

              <p>
                This link expires in 1 hour.
              </p>

              <p>
                If you did not request this,
                you can ignore this email.
              </p>
            </div>
          `
        })
      }
    );

  if (!response.ok) {
    throw new Error(
      `Password reset email failed (${response.status}).`
    );
  }

  return {
    sent: true
  };
}

// --------------------------------------------------
// Health
// --------------------------------------------------

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      success: true,

      service:
        "ScamRatio API",

      status:
        "online",

      timestamp:
        new Date().toISOString(),

      virusTotalConfigured:
        Boolean(
          process.env.VIRUSTOTAL_API_KEY
        ),

      databaseConfigured:
        Boolean(
          process.env.DATABASE_URL
        ),

      databaseReady
    });
  }
);

// --------------------------------------------------
// Authentication API
// --------------------------------------------------

app.post(
  "/api/auth/register",
  async (req, res) => {
    if (
      !isAllowedAuthOrigin(req)
    ) {
      return res.status(403).json({
        success: false,
        error:
          "Origin is not allowed."
      });
    }

    if (!requireDatabase(res)) {
      return;
    }

    try {
      const email =
        String(
          req.body?.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body?.password || ""
        );

      const name =
        String(
          req.body?.name ||
          req.body?.fullName ||
          ""
        )
          .trim()
          .slice(0, 120);

      if (
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
          email
        )
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Please enter a valid email address."
        });
      }

      if (
        password.length < 8 ||
        password.length > 128
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Password must be between 8 and 128 characters."
        });
      }

      const exists =
        await pool.query(
          `SELECT id
           FROM users
           WHERE email = $1
           LIMIT 1`,
          [email]
        );

      if (
        exists.rows.length
      ) {
        return res.status(409).json({
          success: false,
          error:
            "An account with that email already exists."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const result =
        await pool.query(
          `INSERT INTO users
             (email, password_hash, name)
           VALUES
             ($1, $2, $3)
           RETURNING
             id, email, name, created_at`,
          [
            email,
            passwordHash,
            name || null
          ]
        );

      const user =
        result.rows[0];

      const token =
        createAuthToken(
          user.id,
          true
        );

      res.cookie(
        "scamratio_token",
        token,
        getAuthCookieOptions(true)
      );

      return res.status(201).json({
        success: true,

        message:
          "Account created successfully.",

        token,

        user:
          sanitizeUser(user)
      });
    } catch (error) {
      console.error(
        "POST /api/auth/register error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Unable to create your account right now."
      });
    }
  }
);

app.post(
  "/api/auth/login",
  async (req, res) => {
    if (
      !isAllowedAuthOrigin(req)
    ) {
      return res.status(403).json({
        success: false,
        error:
          "Origin is not allowed."
      });
    }

    if (!requireDatabase(res)) {
      return;
    }

    try {
      const email =
        String(
          req.body?.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body?.password || ""
        );

      const rememberMe =
        getRememberMe(
          req.body
        );

      if (
        !email ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Email and password are required."
        });
      }

      const result =
        await pool.query(
          `SELECT
             id,
             email,
             name,
             password_hash,
             created_at
           FROM users
           WHERE email = $1
           LIMIT 1`,
          [email]
        );

      if (
        !result.rows.length
      ) {
        return res.status(401).json({
          success: false,
          error:
            "Invalid email or password."
        });
      }

      const user =
        result.rows[0];

      const matches =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!matches) {
        return res.status(401).json({
          success: false,
          error:
            "Invalid email or password."
        });
      }

      const token =
        createAuthToken(
          user.id,
          rememberMe
        );

      res.cookie(
        "scamratio_token",
        token,
        getAuthCookieOptions(
          rememberMe
        )
      );

      return res.json({
        success: true,

        message:
          "Login successful.",

        token,

        user:
          sanitizeUser(user)
      });
    } catch (error) {
      console.error(
        "POST /api/auth/login error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Unable to log in right now."
      });
    }
  }
);

app.get(
  "/api/auth/me",
  async (req, res) => {
    if (!requireDatabase(res)) {
      return;
    }

    try {
      const user =
        await getAuthenticatedUser(
          req
        );

      if (!user) {
        return res.status(401).json({
          success: false,
          authenticated: false,
          error:
            "Not authenticated."
        });
      }

      return res.json({
        success: true,

        authenticated:
          true,

        user:
          sanitizeUser(user)
      });
    } catch (error) {
      console.error(
        "GET /api/auth/me error:",
        error
      );

      return res.status(500).json({
        success: false,
        authenticated: false,
        error:
          "Unable to verify the current session."
      });
    }
  }
);

app.post(
  "/api/auth/logout",
  (req, res) => {
    if (
      !isAllowedAuthOrigin(req)
    ) {
      return res.status(403).json({
        success: false,
        error:
          "Origin is not allowed."
      });
    }

    res.clearCookie(
      "scamratio_token",
      {
        httpOnly: true,

        secure:
          Boolean(
            process.env.RENDER
          ),

        sameSite:
          process.env.RENDER
            ? "none"
            : "lax",

        path: "/"
      }
    );

    return res.json({
      success: true,

      message:
        "Logged out successfully."
    });
  }
);

app.post(
  "/api/auth/forgot-password",
  async (req, res) => {
    if (
      !isAllowedAuthOrigin(req)
    ) {
      return res.status(403).json({
        success: false,
        error:
          "Origin is not allowed."
      });
    }

    if (!requireDatabase(res)) {
      return;
    }

    try {
      const email =
        String(
          req.body?.email || ""
        )
          .trim()
          .toLowerCase();

      if (
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
          email
        )
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Please enter a valid email address."
        });
      }

      const result =
        await pool.query(
          `SELECT id, email
           FROM users
           WHERE email = $1
           LIMIT 1`,
          [email]
        );

      if (
        !result.rows.length
      ) {
        return res.json({
          success: true,

          message:
            "If an account exists for that email, a password reset link has been sent."
        });
      }

      const rawToken =
        crypto
          .randomBytes(32)
          .toString("hex");

      const tokenHash =
        crypto
          .createHash("sha256")
          .update(rawToken)
          .digest("hex");

      await pool.query(
        `UPDATE users
         SET
           reset_token_hash = $1,
           reset_token_expires_at =
             NOW() + INTERVAL '1 hour',
           updated_at = NOW()
         WHERE id = $2`,
        [
          tokenHash,
          result.rows[0].id
        ]
      );

      const appUrl =
        (
          process.env.PUBLIC_APP_URL ||
          "https://muhammadumar4412667.github.io/Scam-Ratio"
        ).replace(
          /\/$/,
          ""
        );

      const resetUrl =
        `${appUrl}/reset-password.html?token=${encodeURIComponent(
          rawToken
        )}`;

      const emailResult =
        await sendPasswordResetEmail(
          email,
          resetUrl
        );

      if (
        !emailResult.sent
      ) {
        console.error(
          "Password reset requested, but RESEND_API_KEY and AUTH_FROM_EMAIL are not configured."
        );

        return res.status(503).json({
          success: false,
          error:
            "Password reset email service is not configured yet."
        });
      }

      return res.json({
        success: true,

        message:
          "If an account exists for that email, a password reset link has been sent."
      });
    } catch (error) {
      console.error(
        "POST /api/auth/forgot-password error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Unable to process the password reset request right now."
      });
    }
  }
);

app.post(
  "/api/auth/reset-password",
  async (req, res) => {
    if (
      !isAllowedAuthOrigin(req)
    ) {
      return res.status(403).json({
        success: false,
        error:
          "Origin is not allowed."
      });
    }

    if (!requireDatabase(res)) {
      return;
    }

    try {
      const token =
        String(
          req.body?.token || ""
        ).trim();

      const password =
        String(
          req.body?.password || ""
        );

      if (
        !token ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Reset token and new password are required."
        });
      }

      if (
        password.length < 8 ||
        password.length > 128
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Password must be between 8 and 128 characters."
        });
      }

      const tokenHash =
        crypto
          .createHash("sha256")
          .update(token)
          .digest("hex");

      const result =
        await pool.query(
          `SELECT id
           FROM users
           WHERE
             reset_token_hash = $1
             AND reset_token_expires_at > NOW()
           LIMIT 1`,
          [tokenHash]
        );

      if (
        !result.rows.length
      ) {
        return res.status(400).json({
          success: false,
          error:
            "The password reset link is invalid or has expired."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      await pool.query(
        `UPDATE users
         SET
           password_hash = $1,
           reset_token_hash = NULL,
           reset_token_expires_at = NULL,
           updated_at = NOW()
         WHERE id = $2`,
        [
          passwordHash,
          result.rows[0].id
        ]
      );

      return res.json({
        success: true,

        message:
          "Your password has been reset successfully."
      });
    } catch (error) {
      console.error(
        "POST /api/auth/reset-password error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Unable to reset your password right now."
      });
    }
  }
);

app.get(
  "/api/auth/google",
  (req, res) => {
    return res.status(501).json({
      success: false,
      error:
        "Google login is not configured yet."
    });
  }
);

// --------------------------------------------------
// Scam checker API
// --------------------------------------------------

app.post(
  "/api/check",
  async (req, res) => {
    try {
      const input =
        req.body?.url ||
        req.body?.domain;

      if (!input) {
        return res.status(400).json({
          success: false,
          error:
            "Please provide a website URL."
        });
      }

      return res.json(
        await performScamCheck(
          input
        )
      );
    } catch (error) {
      console.error(
        "POST /api/check error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "Website check failed."
      });
    }
  }
);

app.get(
  "/api/check",
  async (req, res) => {
    try {
      const input =
        req.query.url ||
        req.query.domain;

      if (!input) {
        return res.status(400).json({
          success: false,
          error:
            "Please provide a website URL."
        });
      }

      return res.json(
        await performScamCheck(
          input
        )
      );
    } catch (error) {
      console.error(
        "GET /api/check error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "Website check failed."
      });
    }
  }
);

// --------------------------------------------------
// Website routes
// --------------------------------------------------

app.get(
  "/",
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

app.get(
  "/result",
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "result.html"
      )
    );
  }
);

app.get(
  "/login",
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "login.html"
      )
    );
  }
);

// --------------------------------------------------
// 404 / error handlers
// --------------------------------------------------

app.use(
  (req, res) => {
    if (
      req.path.startsWith("/api/")
    ) {
      return res.status(404).json({
        success: false,
        error:
          "API endpoint not found."
      });
    }

    return res
      .status(404)
      .send(
        "Page not found."
      );
  }
);

app.use(
  (error, req, res, next) => {
    console.error(
      "Server error:",
      error
    );

    if (
      req.path.startsWith("/api/")
    ) {
      return res.status(500).json({
        success: false,
        error:
          "Internal server error."
      });
    }

    return res
      .status(500)
      .send(
        "Internal server error."
      );
  }
);

// --------------------------------------------------
// Start server
// --------------------------------------------------

async function startServer() {
  try {
    await initDatabase();

    app.listen(
      PORT,
      () => {
        console.log(
          "======================================"
        );

        console.log(
          "        ScamRatio API Server"
        );

        console.log(
          "======================================"
        );

        console.log(
          `Server running on port ${PORT}`
        );

        console.log(
          `http://localhost:${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);
  }
}

startServer();
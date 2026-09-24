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

const app = express();
const PORT = process.env.PORT || 3000;

// --------------------------------------------------
// Middleware
// --------------------------------------------------

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Serve website files
app.use(express.static(path.join(__dirname, "public")));

// --------------------------------------------------
// Helpers
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

  // Common two-level public suffix patterns.
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

  if (secondLevelTlds.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }

  return parts.slice(-2).join(".");
}

// --------------------------------------------------
// Basic Website / URL Analysis
// --------------------------------------------------

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
}// --------------------------------------------------
// DNS Analysis
// --------------------------------------------------

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
    const mxRecords = await dns.resolveMx(hostname);

    result.mx = mxRecords
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
    const txtRecords = await dns.resolveTxt(hostname);

    result.txt = txtRecords.map((record) => record.join(""));
  } catch {
    result.txt = [];
  }

  return result;
}

// --------------------------------------------------
// SSL Certificate Check
// --------------------------------------------------

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

// --------------------------------------------------
// Domain Intelligence / RDAP
// --------------------------------------------------

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

    // Registrar
    if (Array.isArray(data.entities)) {
      const registrarEntity = data.entities.find((entity) =>
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

    // Events
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
            Math.floor((Date.now() - createdTime) / 86400000)
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

    // Domain status
    if (Array.isArray(data.status)) {
      result.status = data.status;
    }

    // Nameservers
    if (Array.isArray(data.nameservers)) {
      result.nameservers = data.nameservers
        .map((server) => server.ldhName || server.unicodeName)
        .filter(Boolean);
    }

    // DNSSEC
    if (typeof data.secureDNS === "object") {
      result.dnssec = Boolean(data.secureDNS.delegationSigned);
    }

    return result;
  } catch (error) {
    result.error = error.message;

    return result;
  }
}// --------------------------------------------------
// VirusTotal Domain Reputation
// --------------------------------------------------

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
    result.error = "VirusTotal domain lookup requires a domain name.";
    return result;
  }

  try {
    const response = await fetch(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`,
      {
        headers: {
          "x-apikey": apiKey,
          Accept: "application/json"
        },
        signal: AbortSignal.timeout(12000)
      }
    );

    if (!response.ok) {
      throw new Error(`VirusTotal returned HTTP ${response.status}`);
    }

    const data = await response.json();

    const attributes = data?.data?.attributes || {};

    const stats = attributes.last_analysis_stats || {};

    result.available = true;
    result.malicious = Number(stats.malicious || 0);
    result.suspicious = Number(stats.suspicious || 0);
    result.harmless = Number(stats.harmless || 0);
    result.undetected = Number(stats.undetected || 0);
    result.timeout = Number(stats.timeout || 0);

    if (typeof attributes.reputation === "number") {
      result.reputation = attributes.reputation;
    }

    if (attributes.last_analysis_date) {
      result.lastAnalysisDate = new Date(
        attributes.last_analysis_date * 1000
      ).toISOString();
    }

    return result;
  } catch (error) {
    result.error = error.message;

    return result;
  }
}

// --------------------------------------------------
// VirusTotal Risk Analysis
// --------------------------------------------------

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
    riskScore += Math.min(virusTotal.malicious * 12, 60);

    warnings.push({
      type: "virustotal",
      message:
        `VirusTotal reports ${virusTotal.malicious} security engine(s) flagging this domain as malicious.`
    });
  }

  if (virusTotal.suspicious > 0) {
    riskScore += Math.min(virusTotal.suspicious * 5, 25);

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

// --------------------------------------------------
// Domain Intelligence Risk Analysis
// --------------------------------------------------

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

  if (
    typeof domainInfo.ageDays === "number" &&
    domainInfo.ageDays < 30
  ) {
    riskScore += 35;

    warnings.push({
      type: "domain-age",
      message:
        "The domain appears to be less than 30 days old."
    });
  } else if (
    typeof domainInfo.ageDays === "number" &&
    domainInfo.ageDays < 90
  ) {
    riskScore += 20;

    warnings.push({
      type: "domain-age",
      message:
        "The domain appears to be less than 90 days old."
    });
  } else if (
    typeof domainInfo.ageDays === "number" &&
    domainInfo.ageDays < 365
  ) {
    riskScore += 8;

    warnings.push({
      type: "domain-age",
      message:
        "The domain is less than one year old."
    });
  } else if (typeof domainInfo.ageDays === "number") {
    positives.push({
      type: "domain-age",
      message:
        "The domain has been registered for more than one year."
    });
  }

  if (
    typeof domainInfo.daysUntilExpiry === "number" &&
    domainInfo.daysUntilExpiry < 0
  ) {
    riskScore += 30;

    warnings.push({
      type: "domain-expiry",
      message:
        "The domain registration appears to have expired."
    });
  } else if (
    typeof domainInfo.daysUntilExpiry === "number" &&
    domainInfo.daysUntilExpiry < 30
  ) {
    riskScore += 10;

    warnings.push({
      type: "domain-expiry",
      message:
        "The domain registration is due to expire within 30 days."
    });
  }

  if (domainInfo.registrar) {
    positives.push({
      type: "domain",
      message:
        `Registrar information is available: ${domainInfo.registrar}.`
    });
  }

  if (domainInfo.nameservers && domainInfo.nameservers.length > 0) {
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
}// --------------------------------------------------
// Overall Scam Check
// --------------------------------------------------

async function performScamCheck(input) {
  const url = normalizeUrl(input);

  if (!url) {
    throw new Error("Please enter a valid website URL.");
  }

  const hostname = url.hostname.toLowerCase();

  const domainAnalysis = analyzeDomain(url);

  const [
    dnsResult,
    sslResult,
    domainIntelligence,
    virusTotal
  ] = await Promise.all([
    checkDns(hostname),
    checkSsl(hostname),
    checkDomainIntelligence(hostname),
    checkVirusTotal(getRootDomain(hostname))
  ]);

  const vtAnalysis = analyzeVirusTotal(virusTotal);
  const domainInfoAnalysis =
    analyzeDomainIntelligence(domainIntelligence);

  let riskScore = 0;

  const warnings = [];
  const positives = [];

  // --------------------------------------------------
  // URL / domain signals
  // --------------------------------------------------

  riskScore += domainAnalysis.riskScore;

  warnings.push(...domainAnalysis.warnings);
  positives.push(...domainAnalysis.positives);

  // --------------------------------------------------
  // DNS signals
  // --------------------------------------------------

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

  // --------------------------------------------------
  // SSL signals
  // --------------------------------------------------

  if (url.protocol === "https:") {
    if (sslResult.available && sslResult.valid) {
      positives.push({
        type: "ssl",
        message:
          "The website has a valid SSL/TLS certificate."
      });
    } else if (!sslResult.available) {
      warnings.push({
        type: "ssl",
        message:
          "HTTPS is being used, but the SSL certificate could not be fully verified."
      });

      riskScore += 8;
    } else {
      riskScore += 25;

      warnings.push({
        type: "ssl",
        message:
          "The SSL/TLS certificate could not be verified as valid."
      });
    }
  }

  // --------------------------------------------------
  // Domain intelligence
  // --------------------------------------------------

  riskScore += domainInfoAnalysis.riskScore;

  warnings.push(...domainInfoAnalysis.warnings);
  positives.push(...domainInfoAnalysis.positives);

  // --------------------------------------------------
  // VirusTotal
  // --------------------------------------------------

  riskScore += vtAnalysis.riskScore;

  warnings.push(...vtAnalysis.warnings);
  positives.push(...vtAnalysis.positives);

  // --------------------------------------------------
  // Important VirusTotal minimum thresholds
  // --------------------------------------------------

  if (virusTotal.available) {
    if (virusTotal.malicious >= 5) {
      riskScore = Math.max(riskScore, 80);
    } else if (virusTotal.malicious >= 2) {
      riskScore = Math.max(riskScore, 70);
    }
  }

  // --------------------------------------------------
  // Clamp final risk score
  // --------------------------------------------------

  riskScore = Math.max(
    0,
    Math.min(Math.round(riskScore), 100)
  );

  // --------------------------------------------------
  // Risk level
  // --------------------------------------------------

  let riskLevel;
  let status;

  if (riskScore >= 70) {
    riskLevel = "High Risk";
    status = "danger";
  } else if (riskScore >= 40) {
    riskLevel = "Medium Risk";
    status = "warning";
  } else {
    riskLevel = "Low Risk";
    status = "safe";
  }

  // --------------------------------------------------
  // Final positive signals
  // --------------------------------------------------

  const finalPositives = [];

  const addPositive = (message, type = "general") => {
    if (
      message &&
      !finalPositives.some(
        (item) => item.message === message
      )
    ) {
      finalPositives.push({
        type,
        message
      });
    }
  };

  if (url.protocol === "https:") {
    addPositive(
      "HTTPS is enabled.",
      "security"
    );
  }

  if (sslResult.available && sslResult.valid) {
    addPositive(
      "The SSL certificate is valid.",
      "ssl"
    );
  }

  if (dnsResult.available) {
    addPositive(
      "DNS resolution is working.",
      "dns"
    );
  }

  for (const item of positives) {
    if (typeof item === "string") {
      addPositive(item);
    } else if (item && item.message) {
      addPositive(item.message, item.type);
    }
  }

  // --------------------------------------------------
  // Final warnings
  // --------------------------------------------------

  const finalWarnings = [];

  const addWarning = (message, type = "general") => {
    if (
      message &&
      !finalWarnings.some(
        (item) => item.message === message
      )
    ) {
      finalWarnings.push({
        type,
        message
      });
    }
  };

  for (const item of warnings) {
    if (typeof item === "string") {
      addWarning(item);
    } else if (item && item.message) {
      addWarning(item.message, item.type);
    }
  }

  // --------------------------------------------------
  // Summary
  // --------------------------------------------------

  let summary;

  if (riskScore >= 70) {
    summary =
      "Multiple risk signals were detected. Review the warnings carefully before trusting this website.";
  } else if (riskScore >= 40) {
    summary =
      "Some risk signals were detected. Review the available website information before trusting it.";
  } else if (finalWarnings.length > 0) {
    summary =
      "The website has a relatively low overall risk score, but some signals should still be reviewed.";
  } else {
    summary =
      "No major warning signals were detected by the checks currently available.";
  }

  // --------------------------------------------------
  // Trust determination
  // --------------------------------------------------

  const domainOldEnough =
    typeof domainIntelligence.ageDays === "number" &&
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

  if (trusted && riskScore < 5) {
    riskScore = 5;
  }

  return {
    success: true,

    checkedAt: new Date().toISOString(),

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
        enabled: url.protocol === "https:",
        valid: sslResult.valid
      },

      dnsAvailable: dnsResult.available,

      ipAddresses: dnsResult.addresses,

      ssl: sslResult,

      domainAge: {
        available:
          typeof domainIntelligence.ageDays === "number",
        ageDays: domainIntelligence.ageDays,
        created: domainIntelligence.created
      },

      domainIntelligence,

      dns: dnsResult,

      virusTotal
    },

    warnings: finalWarnings.map(
      (item) => item.message
    ),

    positives: finalPositives.map(
      (item) => item.message
    ),

    disclaimer:
      "ScamRatio provides automated website risk signals and does not guarantee that a website is safe or fraudulent."
  };
}// --------------------------------------------------
// API Health Check
// --------------------------------------------------

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "ScamRatio API",
    status: "online",
    timestamp: new Date().toISOString(),
    virusTotalConfigured:
      Boolean(process.env.VIRUSTOTAL_API_KEY)
  });
});

// --------------------------------------------------
// POST /api/check
// --------------------------------------------------

app.post("/api/check", async (req, res) => {
  try {
    const input = req.body?.url || req.body?.domain;

    if (!input) {
      return res.status(400).json({
        success: false,
        error: "Please provide a website URL."
      });
    }

    const result = await performScamCheck(input);

    res.json(result);
  } catch (error) {
    console.error("POST /api/check error:", error);

    res.status(500).json({
      success: false,
      error: error.message || "Website check failed."
    });
  }
});

// --------------------------------------------------
// GET /api/check
// --------------------------------------------------

app.get("/api/check", async (req, res) => {
  try {
    const input = req.query.url || req.query.domain;

    if (!input) {
      return res.status(400).json({
        success: false,
        error: "Please provide a website URL."
      });
    }

    const result = await performScamCheck(input);

    res.json(result);
  } catch (error) {
    console.error("GET /api/check error:", error);

    res.status(500).json({
      success: false,
      error: error.message || "Website check failed."
    });
  }
});// --------------------------------------------------
// Website Routes
// --------------------------------------------------

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

app.get("/result", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "result.html")
  );
});

// --------------------------------------------------
// 404 Handler
// --------------------------------------------------

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      success: false,
      error: "API endpoint not found."
    });
  }

  res.status(404).send("Page not found.");
});

// --------------------------------------------------
// Error Handler
// --------------------------------------------------

app.use((error, req, res, next) => {
  console.error("Server error:", error);

  if (req.path.startsWith("/api/")) {
    return res.status(500).json({
      success: false,
      error: "Internal server error."
    });
  }

  res.status(500).send("Internal server error.");
});

// --------------------------------------------------
// Start Server
// --------------------------------------------------

app.listen(PORT, () => {
  console.log("");
  console.log("======================================");
  console.log("        ScamRatio API Server");
  console.log("======================================");
  console.log(`Server running on port ${PORT}`);
  console.log(`http://localhost:${PORT}`);
  console.log("");
});
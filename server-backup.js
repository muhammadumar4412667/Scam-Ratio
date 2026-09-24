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

// Serve your website files
app.use(express.static(path.join(__dirname, "public")));

// --------------------------------------------------
// Helpers
// --------------------------------------------------

function normalizeUrl(input) {
  if (!input || typeof input !== "string") {
    return null;
  }

  let value = input.trim();

  if (!value) {
    return null;
  }

  // Add protocol if user didn't enter one
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

// --------------------------------------------------
// Basic Website Analysis
// --------------------------------------------------

function analyzeDomain(url) {
  const hostname = url.hostname.toLowerCase();

  let riskScore = 0;
  const warnings = [];
  const positives = [];

  // HTTPS
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

  // IP address instead of domain
  if (net.isIP(hostname)) {
    riskScore += 30;

    warnings.push({
      type: "domain",
      message: "The website uses an IP address instead of a normal domain."
    });
  }

  // Suspicious characters
  if (hostname.includes("@")) {
    riskScore += 20;

    warnings.push({
      type: "domain",
      message: "The URL contains an unusual @ character."
    });
  }

  // Very long domain
  if (hostname.length > 50) {
    riskScore += 10;

    warnings.push({
      type: "domain",
      message: "The domain name is unusually long."
    });
  }

  // Too many subdomains
  const parts = hostname.split(".");

  if (parts.length >= 5) {
    riskScore += 10;

    warnings.push({
      type: "domain",
      message:
        "The domain contains an unusually large number of subdomains."
    });
  }

  // Suspicious keywords
  const suspiciousWords = [
    "verify",
    "verification",
    "secure-login",
    "account-update",
    "claim",
    "bonus",
    "free-money",
    "gift",
    "wallet",
    "crypto",
    "airdrop",
    "prize"
  ];

  const foundWords = suspiciousWords.filter((word) =>
    hostname.includes(word)
  );

  if (foundWords.length > 0) {
    riskScore += Math.min(foundWords.length * 8, 25);

    warnings.push({
      type: "domain",
      message: `Domain contains potentially suspicious keywords: ${foundWords.join(
        ", "
      )}.`
    });
  }

  // Punycode
  if (hostname.includes("xn--")) {
    riskScore += 15;

    warnings.push({
      type: "domain",
      message:
        "The domain uses Punycode, which can sometimes be used for look-alike domains."
    });
  }

  return {
    riskScore,
    warnings,
    positives
  };
}

// --------------------------------------------------
// DNS Analysis
// --------------------------------------------------

async function analyzeDns(hostname) {
  try {
    const addresses = await dns.lookup(hostname, {
      all: true
    });

    const ips = addresses.map((entry) => entry.address);
    const privateAddress = ips.some(isPrivateIp);

    return {
      available: true,
      ips,
      privateAddress
    };
  } catch (error) {
    return {
      available: false,
      ips: [],
      privateAddress: false,
      error: error.message
    };
  }
}

// --------------------------------------------------
// Risk Calculation
// --------------------------------------------------

function getRiskLevel(score) {
  if (score >= 70) {
    return {
      level: "High Risk",
      status: "danger"
    };
  }

  if (score >= 40) {
    return {
      level: "Medium Risk",
      status: "warning"
    };
  }

  return {
    level: "Low Risk",
    status: "safe"
  };
}

function calculateScore(baseScore, dnsResult) {
  let score = baseScore;

  if (!dnsResult.available) {
    score += 10;
  }

  if (dnsResult.privateAddress) {
    score += 20;
  }

  return Math.min(Math.max(score, 0), 100);
}

// --------------------------------------------------
// Real SSL certificate check
// --------------------------------------------------

function checkSsl(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        timeout: 6000,
        rejectUnauthorized: false
      },
      () => {
        const cert = socket.getPeerCertificate();
        const valid = socket.authorized;
        const reason = socket.authorizationError;

        socket.end();

        if (!cert || !cert.valid_to) {
          return resolve({ available: false });
        }

        const expires = new Date(cert.valid_to);

        resolve({
          available: true,
          valid,
          error: valid ? null : String(reason),
          expires: expires.toISOString(),
          daysLeft: Math.floor((expires - Date.now()) / 86400000),
          issuer:
            (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || null
        });
      }
    );

    socket.on("error", (e) =>
      resolve({
        available: false,
        error: e.message
      })
    );

    socket.on("timeout", () => {
      socket.destroy();

      resolve({
        available: false,
        error: "Connection timed out"
      });
    });
  });
}

// --------------------------------------------------
// Domain age (free RDAP lookup, no API key)
// --------------------------------------------------

async function checkDomainAge(hostname) {
  const parts = hostname.split(".");
  let root = parts.slice(-2).join(".");

  // Handle names like example.co.uk
  if (
    parts.length >= 3 &&
    parts[parts.length - 1].length === 2 &&
    ["co", "com", "org", "net", "gov", "edu", "ac"].includes(
      parts[parts.length - 2]
    )
  ) {
    root = parts.slice(-3).join(".");
  }

  try {
    const res = await fetch(`https://rdap.org/domain/${root}`, {
      signal: AbortSignal.timeout(7000),
      headers: {
        accept: "application/rdap+json"
      }
    });

    if (!res.ok) {
      return {
        available: false
      };
    }

    const data = await res.json();

    const reg = (data.events || []).find(
      (event) => event.eventAction === "registration"
    );

    if (!reg) {
      return {
        available: false
      };
    }

    const created = new Date(reg.eventDate);

    return {
      available: true,
      root,
      created: created.toISOString(),
      ageDays: Math.floor((Date.now() - created) / 86400000)
    };
  } catch {
    return {
      available: false
    };
  }
}// --------------------------------------------------
// VirusTotal Domain Reputation
// --------------------------------------------------

async function checkVirusTotalDomain(hostname) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey) {
    return {
      available: false,
      error: "VirusTotal API key is not configured."
    };
  }

  try {
    const response = await fetch(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(
        hostname
      )}`,
      {
        method: "GET",
        headers: {
          "x-apikey": apiKey,
          accept: "application/json"
        },
        signal: AbortSignal.timeout(10000)
      }
    );

    if (!response.ok) {
      let errorMessage = `VirusTotal returned HTTP ${response.status}.`;

      if (response.status === 401 || response.status === 403) {
        errorMessage =
          "VirusTotal rejected the API key or the API request is not authorized.";
      } else if (response.status === 429) {
        errorMessage =
          "VirusTotal API rate limit reached. Please try again later.";
      }

      return {
        available: false,
        statusCode: response.status,
        error: errorMessage
      };
    }

    const data = await response.json();
    const attributes = data?.data?.attributes || {};
    const stats = attributes.last_analysis_stats || {};

    return {
      available: true,
      malicious: Number(stats.malicious || 0),
      suspicious: Number(stats.suspicious || 0),
      harmless: Number(stats.harmless || 0),
      undetected: Number(stats.undetected || 0),
      timeout: Number(stats.timeout || 0),
      reputation: Number(attributes.reputation || 0),
      categories: attributes.categories || {},
      lastAnalysisDate: attributes.last_analysis_date
        ? new Date(attributes.last_analysis_date * 1000).toISOString()
        : null
    };
  } catch (error) {
    return {
      available: false,
      error: error.message || "VirusTotal request failed."
    };
  }
}

// --------------------------------------------------
// Convert VirusTotal findings into ScamRatio risk
// --------------------------------------------------

function analyzeVirusTotal(vt) {
  let risk = 0;
  const warnings = [];
  const positives = [];

  if (!vt || !vt.available) {
    return {
      risk,
      warnings,
      positives
    };
  }

  const malicious = vt.malicious || 0;
  const suspicious = vt.suspicious || 0;
  const harmless = vt.harmless || 0;

  // Malicious detections are the strongest VirusTotal signal.
  if (malicious > 0) {
    risk += Math.min(60, malicious * 12);

    warnings.push({
      type: "virustotal",
      message: `VirusTotal reports ${malicious} security engine(s) flagging this domain as malicious.`
    });
  }

  // Suspicious detections are a weaker signal.
  if (suspicious > 0) {
    risk += Math.min(25, suspicious * 5);

    warnings.push({
      type: "virustotal",
      message: `VirusTotal reports ${suspicious} security engine(s) flagging this domain as suspicious.`
    });
  }

  // Positive signal when VT has meaningful harmless detections and no
  // malicious/suspicious detections.
  if (malicious === 0 && suspicious === 0 && harmless > 0) {
    positives.push({
      type: "virustotal",
      message: `VirusTotal currently reports no malicious or suspicious detections across ${harmless} security engine(s).`
    });
  }

  // Community reputation is useful as a supporting signal, not as proof.
  if (vt.reputation < -10) {
    risk += 15;

    warnings.push({
      type: "virustotal",
      message: `VirusTotal community reputation for this domain is negative (${vt.reputation}).`
    });
  } else if (vt.reputation > 10 && malicious === 0 && suspicious === 0) {
    positives.push({
      type: "virustotal",
      message: `VirusTotal community reputation is positive (${vt.reputation}).`
    });
  }

  return {
    risk,
    warnings,
    positives
  };
}

// --------------------------------------------------
// Main Scam Check
// --------------------------------------------------

async function performScamCheck(input) {
  const url = normalizeUrl(input);

  if (!url) {
    throw new Error("Please enter a valid website URL.");
  }

  const domainAnalysis = analyzeDomain(url);
  const dnsAnalysis = await analyzeDns(url.hostname);

  // Only contact real public websites
  // Never probe IPs or private/internal addresses.
  const canProbe =
    !net.isIP(url.hostname) &&
    dnsAnalysis.available &&
    !dnsAnalysis.privateAddress;

  // VirusTotal works with domain names.
  const canCheckVirusTotal = !net.isIP(url.hostname);

  const [ssl, age, virusTotal] = await Promise.all([
    canProbe
      ? checkSsl(url.hostname)
      : Promise.resolve({ available: false }),

    canProbe
      ? checkDomainAge(url.hostname)
      : Promise.resolve({ available: false }),

    canCheckVirusTotal
      ? checkVirusTotalDomain(url.hostname)
      : Promise.resolve({
          available: false,
          error: "VirusTotal domain lookup is not available for IP addresses."
        })
  ]);

  let extraRisk = 0;
  const extraWarnings = [];
  const extraPositives = [];

  // --------------------------------------------------
  // SSL certificate
  // --------------------------------------------------

  if (canProbe && url.protocol === "https:") {
    if (!ssl.available) {
      extraRisk += 15;

      extraWarnings.push({
        type: "security",
        message: "Could not verify the website's SSL certificate."
      });
    } else if (!ssl.valid) {
      extraRisk += 30;

      extraWarnings.push({
        type: "security",
        message: `The SSL certificate is not valid (${ssl.error}).`
      });
    } else {
      extraPositives.push({
        type: "security",
        message: `Valid SSL certificate${
          ssl.issuer ? " issued by " + ssl.issuer : ""
        }, expires in ${ssl.daysLeft} days.`
      });
    }
  }

  // --------------------------------------------------
  // Domain age
  // --------------------------------------------------

  if (age.available) {
    if (age.ageDays < 30) {
      extraRisk += 35;

      extraWarnings.push({
        type: "domain",
        message: `This domain was registered only ${age.ageDays} days ago.`
      });
    } else if (age.ageDays < 90) {
      extraRisk += 20;

      extraWarnings.push({
        type: "domain",
        message: `This domain is very new (${age.ageDays} days old).`
      });
    } else if (age.ageDays < 365) {
      extraRisk += 8;

      extraWarnings.push({
        type: "domain",
        message: "This domain is less than one year old."
      });
    } else if (age.ageDays >= 730) {
      extraPositives.push({
        type: "domain",
        message: `The domain has existed for about ${Math.floor(
          age.ageDays / 365
        )} years.`
      });
    }
  }

  // --------------------------------------------------
  // VirusTotal
  // --------------------------------------------------

  const virusTotalAnalysis = analyzeVirusTotal(virusTotal);

  extraRisk += virusTotalAnalysis.risk;
  extraWarnings.push(...virusTotalAnalysis.warnings);
  extraPositives.push(...virusTotalAnalysis.positives);

  // --------------------------------------------------
  // Final score
  // --------------------------------------------------

  let score = calculateScore(
    domainAnalysis.riskScore + extraRisk,
    dnsAnalysis
  );

  // Nothing unknown gets a perfect score.
  const trusted =
    ssl.valid &&
    age.available &&
    age.ageDays >= 730 &&
    virusTotal.available &&
    virusTotal.malicious === 0 &&
    virusTotal.suspicious === 0;

  if (!trusted) {
    score = Math.max(score, 5);
  }

  const risk = getRiskLevel(score);

  // --------------------------------------------------
  // Final API response
  // --------------------------------------------------

  return {
    success: true,

    checkedAt: new Date().toISOString(),

    target: {
      input,
      url: url.toString(),
      domain: url.hostname
    },

    score,

    riskLevel: risk.level,

    status: risk.status,

    summary:
      risk.level === "High Risk"
        ? "This website has several signals that deserve serious caution."
        : risk.level === "Medium Risk"
        ? "This website has some signals that should be reviewed before you trust it."
        : "No major warning signals were detected by the ScamRatio checks.",

    checks: {
      https: url.protocol === "https:",

      dnsAvailable: dnsAnalysis.available,

      ipAddresses: dnsAnalysis.ips,

      ssl,

      domainAge: age,

      virusTotal: {
        available: virusTotal.available,
        malicious: virusTotal.malicious || 0,
        suspicious: virusTotal.suspicious || 0,
        harmless: virusTotal.harmless || 0,
        undetected: virusTotal.undetected || 0,
        timeout: virusTotal.timeout || 0,
        reputation: virusTotal.reputation || 0,
        lastAnalysisDate: virusTotal.lastAnalysisDate || null,
        error: virusTotal.available
          ? null
          : virusTotal.error || null
      }
    },

    warnings: [
      ...domainAnalysis.warnings,
      ...extraWarnings
    ],

    positives: [
      ...domainAnalysis.positives,
      ...extraPositives
    ],

    disclaimer:
      "ScamRatio results are risk indicators, not proof that a website is legitimate or fraudulent."
  };
}// --------------------------------------------------
// API Routes
// --------------------------------------------------

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "ScamRatio API",
    status: "online",
    timestamp: new Date().toISOString(),
    virusTotalConfigured: Boolean(process.env.VIRUSTOTAL_API_KEY)
  });
});

// Main scam checker endpoint
app.post("/api/check", async (req, res) => {
  try {
    const { url, website, domain } = req.body;

    const input = url || website || domain;

    if (!input) {
      return res.status(400).json({
        success: false,
        error: "A website URL or domain is required."
      });
    }

    const result = await performScamCheck(input);

    return res.json(result);
  } catch (error) {
    console.error("Scam check error:", error);

    return res.status(400).json({
      success: false,
      error:
        error.message ||
        "Unable to analyze this website."
    });
  }
});

// GET version for easy testing
app.get("/api/check", async (req, res) => {
  try {
    const input = req.query.url;

    if (!input) {
      return res.status(400).json({
        success: false,
        error: "Use /api/check?url=example.com"
      });
    }

    const result = await performScamCheck(input);

    return res.json(result);
  } catch (error) {
    return res.status(400).json({
      success: false,
      error:
        error.message ||
        "Unable to analyze this website."
    });
  }
});

// --------------------------------------------------
// Frontend Routes
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

  res.status(404).sendFile(
    path.join(__dirname, "public", "404.html"),
    (err) => {
      if (err) {
        res.status(404).send("Page not found.");
      }
    }
  );
});

// --------------------------------------------------
// Error Handler
// --------------------------------------------------

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    success: false,
    error: "Internal server error."
  });
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
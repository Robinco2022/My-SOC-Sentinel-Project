(() => {
  "use strict";

  const MAX_FILE_SIZE = 1_000_000;
  const MAX_LOG_FILE_SIZE = 20 * 1024 * 1024;
  const MAX_LOG_FILES = 20;
  const MAX_LOG_LINES = 20_000;
  const IGNORED_DIRECTORIES = new Set([
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules",
    "__pycache__", "dist", "build",
  ]);
  const SCANNABLE_EXTENSIONS = new Set([
    ".bat", ".c", ".cfg", ".conf", ".cc", ".cmd", ".cpp", ".cs",
    ".dart", ".gradle", ".go", ".h", ".hpp", ".html", ".ini", ".java",
    ".js", ".json", ".jsx", ".kt", ".m", ".mm", ".php", ".pem", ".ps1",
    ".properties", ".py", ".rb", ".rs", ".scala", ".sh", ".sql", ".swift",
    ".tf", ".toml", ".ts", ".tsx", ".vue", ".xml", ".yaml", ".yml",
  ]);
  const SCANNABLE_NAMES = new Set([
    "dockerfile", "makefile", "procfile", ".env", ".env.local", ".env.production",
  ]);
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const rules = [
    {
      id: "PRIVATE-KEY",
      severity: "critical",
      title: "Private key material in a file",
      recommendation: "Remove the key, rotate it, and use a secrets manager or protected key store.",
      pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    },
    {
      id: "HARDCODED-SECRET",
      severity: "high",
      title: "Possible hard-coded credential or API token",
      recommendation: "Remove the value, rotate the credential, and load it from a secrets manager.",
      pattern: /\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret|token)\b\s*[:=]\s*["']?(?!["']?\s*(?:$|none\b|null\b|undefined\b|your[_ -]|example\b|changeme\b|placeholder\b|<))[A-Za-z0-9_./+=:@-]{8,}/i,
    },
    {
      id: "AWS-ACCESS-KEY",
      severity: "high",
      title: "Possible AWS access key ID",
      recommendation: "Revoke the key and use an IAM role or short-lived credentials.",
      pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
    },
    {
      id: "COMMAND-INJECTION",
      severity: "high",
      title: "Shell command execution with shell enabled",
      recommendation: "Avoid shell execution; pass an argument list and validate untrusted input.",
      pattern: /\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^)\n]*\bshell\s*=\s*True/,
    },
    {
      id: "OS-SYSTEM",
      severity: "high",
      title: "Direct shell command execution",
      recommendation: "Avoid os.system; use a subprocess argument list with validated input.",
      pattern: /\bos\.system\s*\(/,
    },
    {
      id: "DYNAMIC-EVAL",
      severity: "high",
      title: "Dynamic code evaluation",
      recommendation: "Avoid eval/exec on input that may be influenced by an untrusted source.",
      pattern: /\b(?:eval|exec)\s*\(/,
    },
    {
      id: "SQL-STRING-FORMAT",
      severity: "high",
      title: "SQL execution may use interpolated or concatenated input",
      recommendation: "Use parameterized queries and bind values separately from SQL text.",
      pattern: /\b(?:execute|executemany|raw|query)\s*\(\s*(?:f["']|["'][^"']*%s|["'][^"']*["']\s*%|["'][^"']*["']\s*\+)/i,
    },
    {
      id: "TLS-VERIFY-DISABLED",
      severity: "high",
      title: "TLS certificate verification disabled",
      recommendation: "Enable certificate verification; do not use this setting in production.",
      pattern: /\b(?:verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False)\b/,
    },
    {
      id: "UNSAFE-PICKLE",
      severity: "high",
      title: "Unsafe deserialization with pickle",
      recommendation: "Do not deserialize untrusted data with pickle; use a safe data format.",
      pattern: /\bpickle\.(?:load|loads)\s*\(/,
    },
    {
      id: "UNSAFE-YAML",
      severity: "high",
      title: "Potentially unsafe YAML deserialization",
      recommendation: "Use yaml.safe_load for data that is not fully trusted.",
      pattern: /\byaml\.load\s*\(/,
      safePattern: /\bLoader\s*=\s*(?:yaml\.)?SafeLoader\b/,
    },
    {
      id: "DEBUG-ENABLED",
      severity: "medium",
      title: "Debug mode may be enabled",
      recommendation: "Disable debug mode in deployed environments.",
      pattern: /\b(?:debug\s*[:=]\s*True|DEBUG\s*=\s*True)\b/i,
    },
    {
      id: "WEAK-HASH",
      severity: "medium",
      title: "Weak hash algorithm used",
      recommendation: "Use a modern hash such as SHA-256; use a password-hashing algorithm for passwords.",
      pattern: /\b(?:hashlib\.(?:md5|sha1)\s*\(|(?:MD5|SHA1)\s*\()/,
    },
    {
      id: "OPEN-CORS",
      severity: "medium",
      title: "Wildcard CORS origin",
      recommendation: "Restrict allowed origins to the specific trusted domains that need access.",
      pattern: /(?:Access-Control-Allow-Origin\s*[:=]\s*["']?\*|CORS_ORIGIN\s*[:=]\s*["']\*)/i,
    },
  ];

  const elements = {
    dropZone: document.querySelector("#drop-zone"),
    fileInput: document.querySelector("#file-input"),
    folderInput: document.querySelector("#folder-input"),
    chooseFiles: document.querySelector("#choose-files"),
    chooseFolder: document.querySelector("#choose-folder"),
    newScan: document.querySelector("#new-scan-button"),
    progress: document.querySelector("#scan-progress"),
    progressLabel: document.querySelector("#progress-label"),
    progressValue: document.querySelector("#progress-value"),
    progressBar: document.querySelector("#progress-bar"),
    message: document.querySelector("#scan-message"),
    warnings: document.querySelector("#scan-warnings"),
    totalFindings: document.querySelector("#total-findings"),
    urgentFindings: document.querySelector("#urgent-findings"),
    filesScanned: document.querySelector("#files-scanned"),
    scanStatus: document.querySelector("#scan-status"),
    scanTime: document.querySelector("#scan-time"),
    findingsFoot: document.querySelector("#findings-foot"),
    findingsCount: document.querySelector("#findings-count"),
    sidebarCount: document.querySelector("#sidebar-count"),
    findingsList: document.querySelector("#findings-list"),
    emptyState: document.querySelector("#empty-state"),
    emptyTitle: document.querySelector("#empty-title"),
    emptyCopy: document.querySelector("#empty-copy"),
    search: document.querySelector("#search-input"),
    severityFilter: document.querySelector("#severity-filter"),
    visibleCount: document.querySelector("#visible-count"),
    footerShowing: document.querySelector("#footer-showing"),
    footerTotal: document.querySelector("#footer-total"),
    exportButton: document.querySelector("#export-button"),
  };

  let findings = [];
  let scanSummary = null;
  let scanning = false;
  let progressHideTimer = null;
  const apiElements = {
    discoverHosts: document.querySelector("#discover-hosts"),
    hostsStatus: document.querySelector("#hosts-status"),
    hostsResults: document.querySelector("#hosts-results"),
    chooseVirusFiles: document.querySelector("#choose-virus-files"),
    virusFileInput: document.querySelector("#virus-file-input"),
    defenderStatus: document.querySelector("#defender-status"),
    virusResults: document.querySelector("#virus-results"),
    webCheckForm: document.querySelector("#web-check-form"),
    webTarget: document.querySelector("#web-target"),
    webCheckButton: document.querySelector("#web-check-button"),
    webResults: document.querySelector("#web-results"),
    logFileInput: document.querySelector("#log-file-input"),
    requestThreshold: document.querySelector("#request-threshold"),
    trafficResults: document.querySelector("#traffic-results"),
  };

  function appendLabeledValue(parent, label, value) {
    const item = document.createElement("div");
    item.className = "tool-list-item";
    item.append(
      createTextElement("strong", "", label),
      createTextElement("span", "", value),
    );
    parent.append(item);
  }

  async function requestApi(path, options) {
    let response;
    try {
      response = await fetch(path, options);
    } catch {
      throw new Error("Local Sentinel service unavailable. Start it with .\\sentinel_server.ps1.");
    }
    let result;
    try {
      result = await response.json();
    } catch {
      throw new Error("Unexpected response from the local Sentinel service.");
    }
    if (!response.ok) throw new Error(result.error || `Local service returned HTTP ${response.status}.`);
    return result;
  }

  async function discoverPrivateHosts() {
    apiElements.discoverHosts.disabled = true;
    apiElements.hostsResults.replaceChildren();
    apiElements.hostsResults.hidden = true;
    apiElements.hostsStatus.classList.remove("tool-error");
    apiElements.hostsStatus.textContent = "Reading the local IPv4 neighbor table...";
    try {
      const result = await requestApi("/api/hosts");
      apiElements.hostsResults.replaceChildren();
      if (result.hosts.length === 0) {
        apiElements.hostsStatus.textContent = "No private IPv4 neighbors are currently listed. The local neighbor cache only shows devices this computer has recently seen.";
        return;
      }
      apiElements.hostsStatus.textContent = `${result.hosts.length} local network neighbor${result.hosts.length === 1 ? "" : "s"} found.`;
      const header = document.createElement("div");
      header.className = "tool-list-header";
      ["IPv4 address", "MAC address", "State"].forEach((label) => {
        header.append(createTextElement("span", "", label));
      });
      apiElements.hostsResults.append(header);
      result.hosts.forEach((host) => {
        const row = document.createElement("div");
        row.className = "tool-list-row";
        row.append(
          createTextElement("span", "mono", host.ip),
          createTextElement("span", "mono", host.mac || "Unavailable"),
          createTextElement("span", "", host.state),
        );
        apiElements.hostsResults.append(row);
      });
      apiElements.hostsResults.hidden = false;
    } catch (error) {
      apiElements.hostsStatus.classList.add("tool-error");
      apiElements.hostsStatus.textContent = error.message;
    } finally {
      apiElements.discoverHosts.disabled = false;
    }
  }

  async function loadDefenderStatus() {
    try {
      const result = await requestApi("/api/defender/status");
      if (!result.available) {
        apiElements.defenderStatus.textContent = "Microsoft Defender unavailable";
        apiElements.defenderStatus.classList.add("capability-unavailable");
        return;
      }
      const state = result.realtimeProtection ? "Defender active" : "Defender protection is off";
      apiElements.defenderStatus.textContent = result.signatureAgeDays == null
        ? state
        : `${state} · signatures ${result.signatureAgeDays}d old`;
      apiElements.defenderStatus.classList.toggle("capability-unavailable", !result.realtimeProtection);
    } catch (error) {
      apiElements.defenderStatus.textContent = error.message;
      apiElements.defenderStatus.classList.add("capability-unavailable");
    }
  }

  async function scanWithDefender(fileList) {
    const files = Array.from(fileList || []);
    if (files.length === 0) return;
    apiElements.virusFileInput.value = "";
    apiElements.chooseVirusFiles.disabled = true;
    apiElements.virusResults.classList.remove("tool-error");
    apiElements.virusResults.replaceChildren();
    apiElements.virusResults.textContent = `Scanning ${files.length} file${files.length === 1 ? "" : "s"} with Microsoft Defender...`;
    for (const file of files) {
      if (file.size > 50 * 1024 * 1024) {
        const warning = document.createElement("div");
        warning.className = "tool-list-item tool-error";
        warning.textContent = `${file.name}: skipped (larger than 50 MB).`;
        apiElements.virusResults.append(warning);
        continue;
      }
      const row = document.createElement("div");
      row.className = "tool-list-item";
      row.textContent = `${file.name}: scanning...`;
      apiElements.virusResults.append(row);
      try {
        const result = await requestApi("/api/defender/scan", {
          method: "POST",
          headers: {
            "Content-Type": "application/octet-stream",
            "X-File-Extension": file.name.includes(".") ? `.${file.name.split(".").pop()}` : ".bin",
          },
          body: file,
        });
        row.classList.toggle("tool-error", result.verdict === "indeterminate");
        row.textContent = `${file.name}: ${result.message}`;
      } catch (error) {
        row.classList.add("tool-error");
        row.textContent = `${file.name}: ${error.message}`;
      }
    }
    apiElements.chooseVirusFiles.disabled = false;
  }

  function renderWebAssessment(result) {
    apiElements.webResults.replaceChildren();
    const summary = document.createElement("div");
    summary.className = "assessment-summary";
    summary.append(
      createTextElement("strong", "", `${result.statusCode} ${result.statusText}`),
      createTextElement("span", "", result.url),
    );
    apiElements.webResults.append(summary);
    const list = document.createElement("div");
    list.className = "assessment-list";
    result.checks.forEach((check) => {
      const item = document.createElement("div");
      item.className = `assessment-item assessment-${check.severity}`;
      item.append(
        createTextElement("span", "assessment-indicator", check.severity === "pass" ? "PASS" : check.severity === "info" ? "INFO" : "REVIEW"),
        createTextElement("strong", "", check.title),
        createTextElement("span", "", check.detail),
      );
      list.append(item);
    });
    apiElements.webResults.append(list);
  }

  function isPrivateIpv4(value) {
    if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return false;
    const octets = value.split(".").map(Number);
    if (octets.some((octet) => octet < 0 || octet > 255)) return false;
    return octets[0] === 127
      || octets[0] === 10
      || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
      || (octets[0] === 192 && octets[1] === 168);
  }

  async function checkPrivateWebService(event) {
    event.preventDefault();
    apiElements.webCheckButton.disabled = true;
    apiElements.webResults.classList.remove("tool-error");
    apiElements.webResults.textContent = "Validating target scope...";
    try {
      const parsedUrl = new URL(apiElements.webTarget.value);
      if (!["http:", "https:"].includes(parsedUrl.protocol)
        || !isPrivateIpv4(parsedUrl.hostname)
        || parsedUrl.username
        || parsedUrl.password
        || parsedUrl.pathname !== "/"
        || parsedUrl.search
        || parsedUrl.hash) {
        throw new Error("Enter an HTTP or HTTPS URL to a private/loopback IPv4 address only, with the root path and no credentials, query, or fragment.");
      }
      const result = await requestApi("/api/web-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: parsedUrl.href }),
      });
      renderWebAssessment(result);
    } catch (error) {
      apiElements.webResults.replaceChildren();
      apiElements.webResults.classList.add("tool-error");
      apiElements.webResults.textContent = error.message;
    } finally {
      apiElements.webCheckButton.disabled = false;
    }
  }

  function parseIpv4Values(text) {
    const found = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    return found.filter((ip) => {
      const octets = ip.split(".").map(Number);
      return octets.every((part) => part >= 0 && part <= 255);
    });
  }

  function parseCsvFields(line) {
    const fields = [];
    let field = "";
    let quoted = false;
    for (let index = 0; index < line.length; index += 1) {
      const character = line[index];
      if (character === '"') {
        if (quoted && line[index + 1] === '"') {
          field += '"';
          index += 1;
        } else {
          quoted = !quoted;
        }
      } else if (character === "," && !quoted) {
        fields.push(field);
        field = "";
      } else {
        field += character;
      }
    }
    fields.push(field);
    return fields;
  }

  function parseDateValue(value) {
    if (value == null || value === "") return null;
    const numeric = Number(value);
    const date = Number.isFinite(numeric) && numeric > 0
      ? new Date(numeric < 100_000_000_000 ? numeric * 1000 : numeric)
      : new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function parseAccessLog(line, csvHeaders) {
    if (csvHeaders) {
      const values = parseCsvFields(line);
      const record = Object.fromEntries(
        csvHeaders.map((name, index) => [name, values[index] ?? ""]),
      );
      const ipValue = ["clientip", "remoteaddr", "remoteaddress", "srcip", "sourceip", "sourceaddress", "ip"]
        .map((key) => record[key])
        .find(Boolean);
      const timestampValue = ["timestamp", "time", "datetime", "eventtime", "date"]
        .map((key) => record[key])
        .find(Boolean);
      const statusValue = ["status", "statuscode", "httpstatus", "responsecode"]
        .map((key) => record[key])
        .find(Boolean);
      const status = Number(statusValue);
      return {
        ip: ipValue && parseIpv4Values(ipValue)[0],
        timestamp: parseDateValue(timestampValue),
        status: statusValue && Number.isFinite(status) ? status : null,
      };
    }

    const apache = line.match(/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"[A-Z]+\s[^"]*"\s(\d{3})\b/);
    if (apache) {
      const [, ip, rawTimestamp, rawStatus] = apache;
      const timestamp = parseApacheTimestamp(rawTimestamp);
      return { ip, timestamp, status: Number(rawStatus) };
    }
    if (line.trimStart().startsWith("{")) {
      try {
        const value = JSON.parse(line);
        if (value && typeof value === "object" && !Array.isArray(value)) {
          const normalized = {};
          for (const [key, item] of Object.entries(value)) {
            normalized[key.toLowerCase().replace(/[^a-z0-9]/g, "")] = item;
          }
          const candidates = ["clientip", "remoteaddr", "remoteaddress", "srcip", "sourceip", "ip"];
          const ipValue = candidates.map((key) => normalized[key]).find((item) => typeof item === "string");
          const timeValue = ["timestamp", "time", "datetime", "@timestamp"].map((key) => normalized[key]).find((item) => typeof item === "string");
          const statusValue = ["status", "statuscode", "httpstatus"].map((key) => normalized[key]).find((item) => item != null);
          return {
            ip: ipValue && parseIpv4Values(ipValue)[0],
            timestamp: parseDateValue(timeValue),
            status: Number.isFinite(Number(statusValue)) ? Number(statusValue) : null,
          };
        }
      } catch {
        return null;
      }
    }
    const ips = parseIpv4Values(line);
    const statusMatch = line.match(/"\s+([1-5]\d\d)\b/);
    const timestampMatch = line.match(/\[([^\]]+)\]/);
    return {
      ip: ips[0],
      timestamp: timestampMatch ? parseApacheTimestamp(timestampMatch[1]) : null,
      status: statusMatch ? Number(statusMatch[1]) : null,
    };
  }

  function parseApacheTimestamp(value) {
    const match = value.match(/^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$/);
    if (!match) {
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? null : date;
    }
    const [, day, month, year, hour, minute, second, zone] = match;
    const monthNumber = {
      Jan: "01", Feb: "02", Mar: "03", Apr: "04", May: "05", Jun: "06",
      Jul: "07", Aug: "08", Sep: "09", Oct: "10", Nov: "11", Dec: "12",
    }[month];
    if (!monthNumber) return null;
    return new Date(`${year}-${monthNumber}-${day}T${hour}:${minute}:${second}${zone.slice(0, 3)}:${zone.slice(3)}`);
  }

  function huntLogs(text, threshold) {
    const allLines = text.split(/\r?\n/, MAX_LOG_LINES + 1);
    const truncated = allLines.length > MAX_LOG_LINES
      && allLines[MAX_LOG_LINES].trim().length > 0;
    const lines = truncated ? allLines.slice(0, MAX_LOG_LINES) : allLines;
    const firstLogLine = lines.findIndex((line) => line.trim());
    const candidateHeaders = firstLogLine >= 0
      ? parseCsvFields(lines[firstLogLine]).map((header) => header.toLowerCase().replace(/[^a-z0-9]/g, ""))
      : [];
    const ipHeaderNames = new Set(["clientip", "remoteaddr", "remoteaddress", "srcip", "sourceip", "sourceaddress", "ip"]);
    const csvHeaders = candidateHeaders.some((header) => ipHeaderNames.has(header))
      ? candidateHeaders
      : null;
    const csvHeaderLine = csvHeaders ? firstLogLine : -1;
    const events = [];
    const suspiciousLines = [];
    const authFailures = new Map();
    let status429 = 0;
    let status5xx = 0;

    lines.forEach((line, index) => {
      if (!line.trim()) return;
      if (index === csvHeaderLine) return;
      const event = parseAccessLog(line, csvHeaders);
      if (event) {
        event.line = index + 1;
        events.push(event);
        if (event.status === 429) status429 += 1;
        if (event.status >= 500 && event.status < 600) status5xx += 1;
      }
      const ip = event?.ip || parseIpv4Values(line)[0] || "unattributed source";
      if (/\b(?:failed|failure|invalid|denied|unauthorized|rejected)\b.{0,50}\b(?:login|logon|authentication|authorization|auth|password|credential)\b|\b(?:login|logon|authentication|authorization|auth|password|credential)\b.{0,50}\b(?:failed|failure|invalid|denied|unauthorized|rejected)\b/i.test(line)) {
        authFailures.set(ip, (authFailures.get(ip) || 0) + 1);
      }
      let indicator = null;
      if (/(?:^|\s)-(?:EncodedCommand|enc)\s+[A-Za-z0-9+/]{20,}|FromBase64String\s*\(/i.test(line)) {
        indicator = { severity: "high", type: "Encoded PowerShell indicator", ip, line: index + 1 };
      } else if (/\bunion\s+(?:all\s+)?select\b|(?:'|%27)\s*or\s+(?:'[^']*'|\d+\s*=\s*\d+)|<\s*script\b/i.test(line)) {
        indicator = { severity: "medium", type: "Web injection probe indicator", ip, line: index + 1 };
      } else if (/(?:\.\.\/|%2e%2e(?:\/|%2f)|\b\/etc\/passwd\b)/i.test(line)) {
        indicator = { severity: "medium", type: "Path traversal probe indicator", ip, line: index + 1 };
      } else if (/\b(?:psexec|mimikatz|credential dumping|lsass\.exe)\b/i.test(line)) {
        indicator = { severity: "high", type: "Credential-access indicator", ip, line: index + 1 };
      }
      if (indicator) suspiciousLines.push(indicator);
    });

    const failures = Array.from(authFailures, ([ip, count]) => ({ ip, count }))
      .filter((entry) => entry.count >= 8)
      .sort((left, right) => right.count - left.count);
    const bursts = new Map();
    const aggregateBuckets = new Map();
    events.forEach((event) => {
      if (!event.ip || !event.timestamp) return;
      const bucket = Math.floor(event.timestamp.getTime() / 60_000);
      const key = `${event.ip}|${bucket}`;
      bursts.set(key, { ip: event.ip, bucket, count: (bursts.get(key)?.count || 0) + 1 });
      const aggregate = aggregateBuckets.get(bucket) || { bucket, count: 0, sources: new Set() };
      aggregate.count += 1;
      aggregate.sources.add(event.ip);
      aggregateBuckets.set(bucket, aggregate);
    });
    const highRates = Array.from(bursts.values())
      .filter((bucket) => bucket.count >= threshold)
      .sort((left, right) => right.count - left.count)
      .slice(0, 20);
    const distributedBursts = Array.from(aggregateBuckets.values())
      .filter((bucket) => bucket.count >= threshold && bucket.sources.size > 1)
      .sort((left, right) => right.count - left.count)
      .slice(0, 20)
      .map((bucket) => ({ ...bucket, sourceCount: bucket.sources.size }));
    return {
      lineCount: lines.filter((line) => line.trim()).length,
      truncated,
      parsedRequests: events.filter((event) => event.ip).length,
      uniqueSources: new Set(events.map((event) => event.ip).filter(Boolean)).size,
      status429,
      status5xx,
      timestampedRequests: events.filter((event) => event.ip && event.timestamp).length,
      bursts: highRates,
      distributedBursts,
      authFailures: failures,
      suspicious: suspiciousLines,
      threshold,
    };
  }

  function renderHuntResults(result, fileName) {
    const report = document.createElement("section");
    report.className = "log-report";
    const heading = document.createElement("div");
    heading.className = "analysis-heading";
    const analyzedLines = result.truncated
      ? `First ${result.lineCount} of more than ${MAX_LOG_LINES.toLocaleString()} log lines analyzed locally`
      : `${result.lineCount} log line${result.lineCount === 1 ? "" : "s"} analyzed locally`;
    heading.append(
      createTextElement("strong", "", `Investigation: ${fileName}`),
      createTextElement("span", "", analyzedLines),
    );
    const metrics = document.createElement("div");
    metrics.className = "analysis-metrics";
    [
      ["Requests parsed", result.parsedRequests],
      ["Unique sources", result.uniqueSources],
      ["HTTP 429", result.status429],
      ["HTTP 5xx", result.status5xx],
    ].forEach(([label, count]) => {
      const item = document.createElement("div");
      item.append(createTextElement("strong", "", String(count)), createTextElement("span", "", label));
      metrics.append(item);
    });
    report.append(heading, metrics);

    const burstTitle = createTextElement("h4", "analysis-subheading", `DDoS indicators · ${result.threshold}+ requests from one source in a minute`);
    report.append(burstTitle);
    if (result.timestampedRequests === 0) {
      report.append(createTextElement("p", "analysis-placeholder", "Could not identify source IPs and timestamps in this log format, so request-rate analysis was not possible."));
    } else if (result.bursts.length === 0) {
      report.append(createTextElement("p", "analysis-placeholder", `No source crossed the configured rate in ${result.timestampedRequests} timestamped requests. This does not rule out a DDoS event.`));
    } else {
      result.bursts.slice(0, 5).forEach((burst) => {
        report.append(createTextElement("div", "hunt-finding severity-high", `${burst.ip} · ${burst.count} requests in one minute · bucket ${new Date(burst.bucket * 60_000).toISOString()}`));
      });
    }
    if (result.distributedBursts.length > 0) {
      report.append(createTextElement("h4", "analysis-subheading", `Distributed-volume indicators · ${result.threshold}+ requests/minute across sources`));
      result.distributedBursts.slice(0, 5).forEach((burst) => {
        report.append(createTextElement("div", "hunt-finding severity-high", `${burst.count} requests from ${burst.sourceCount} sources · bucket ${new Date(burst.bucket * 60_000).toISOString()}`));
      });
    }

    const huntTitle = createTextElement("h4", "analysis-subheading", "Threat-hunting indicators");
    report.append(huntTitle);
    const allIndicators = [
      ...result.authFailures.map((entry) => ({ severity: "medium", type: "Repeated authentication failures", ip: entry.ip, detail: `${entry.count} failures` })),
      ...result.suspicious.map((entry) => ({ ...entry, detail: `line ${entry.line}` })),
    ];
    if (allIndicators.length === 0) {
      report.append(createTextElement("p", "analysis-placeholder", "No configured hunting indicators matched. Absence of these heuristic matches does not establish that a system is safe."));
      apiElements.trafficResults.append(report);
      return;
    }
    allIndicators.slice(0, 30).forEach((indicator) => {
      report.append(createTextElement("div", `hunt-finding severity-${indicator.severity}`, `${indicator.type} · ${indicator.ip} · ${indicator.detail}`));
    });
    if (allIndicators.length > 30) {
      report.append(createTextElement("p", "analysis-placeholder", `${allIndicators.length - 30} additional indicator(s) are not shown.`));
    }
    apiElements.trafficResults.append(report);
  }

  async function analyzeLogFiles(fileList) {
    const files = Array.from(fileList || []);
    apiElements.logFileInput.value = "";
    if (files.length === 0) return;
    const threshold = Number(apiElements.requestThreshold.value);
    if (!Number.isInteger(threshold) || threshold < 10 || threshold > 1_000_000) {
      apiElements.trafficResults.textContent = "Burst threshold must be a whole number from 10 to 1,000,000.";
      return;
    }
    apiElements.trafficResults.replaceChildren();
    let totalBytes = 0;
    if (files.length > MAX_LOG_FILES) {
      apiElements.trafficResults.append(createTextElement("p", "tool-error", `Select no more than ${MAX_LOG_FILES} log files at a time.`));
      return;
    }
    for (const file of files) {
      if (file.size > MAX_LOG_FILE_SIZE || totalBytes + file.size > MAX_LOG_FILE_SIZE) {
        apiElements.trafficResults.append(createTextElement("p", "tool-error", `${file.name}: skipped (larger than 20 MB).`));
        continue;
      }
      totalBytes += file.size;
      try {
        const content = await file.text();
        const result = huntLogs(content, threshold);
        renderHuntResults(result, file.name);
      } catch {
        apiElements.trafficResults.replaceChildren(
          createTextElement("p", "tool-error", `${file.name}: could not be read.`),
        );
      }
    }
    if (apiElements.trafficResults.childElementCount === 0) {
      apiElements.trafficResults.append(createTextElement("p", "analysis-placeholder", "No log files were analyzed."));
    }
  }

  function isScannable(file) {
    const name = file.name.toLowerCase();
    if (SCANNABLE_NAMES.has(name) || (name.startsWith(".env.") && name.length > 5)) {
      return true;
    }
    const lastDot = name.lastIndexOf(".");
    return lastDot >= 0 && SCANNABLE_EXTENSIONS.has(name.slice(lastDot));
  }

  function displayPath(file) {
    return file.webkitRelativePath || file.name;
  }

  function isIgnoredPath(path) {
    return path.split("/").some((part) => IGNORED_DIRECTORIES.has(part.toLowerCase()));
  }

  function updateProgress(completed, total, label) {
    const percentage = total === 0 ? 100 : Math.round((completed / total) * 100);
    elements.progressLabel.textContent = label;
    elements.progressValue.textContent = `${percentage}%`;
    elements.progressBar.style.width = `${percentage}%`;
  }

  function showMessage(message, isError = false) {
    elements.message.textContent = message;
    elements.message.classList.toggle("error", isError);
    elements.message.hidden = !message;
  }

  function createTextElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    element.textContent = text;
    return element;
  }

  function updateMetrics() {
    const urgentCount = findings.filter(
      (finding) => finding.severity === "critical" || finding.severity === "high",
    ).length;
    elements.totalFindings.textContent = String(findings.length);
    elements.urgentFindings.textContent = String(urgentCount);
    elements.filesScanned.textContent = String(scanSummary?.filesScanned ?? 0);
    elements.scanStatus.replaceChildren();
    const statusDot = document.createElement("span");
    statusDot.className = "status-dot";
    elements.scanStatus.append(statusDot, document.createTextNode(" Complete"));
    elements.scanTime.textContent = scanSummary?.duration ?? "Scan complete";
    elements.findingsFoot.textContent = findings.length
      ? `${urgentCount} critical or high priority`
      : "No security issues detected";
    elements.findingsCount.textContent = String(findings.length);
    elements.sidebarCount.textContent = String(findings.length);
    elements.footerTotal.textContent = String(findings.length);
    elements.exportButton.disabled = false;
  }

  function matchesFilters(finding) {
    const severity = elements.severityFilter.value;
    if (severity !== "all" && finding.severity !== severity) return false;
    const query = elements.search.value.trim().toLowerCase();
    if (!query) return true;
    return [
      finding.title,
      finding.rule_id,
      finding.path,
      finding.severity,
      finding.recommendation,
    ].some((value) => value.toLowerCase().includes(query));
  }

  function renderFinding(finding) {
    const row = document.createElement("article");
    row.className = "finding-row";

    const severity = createTextElement(
      "span",
      `severity-badge severity-${finding.severity}`,
      finding.severity,
    );
    const details = document.createElement("div");
    details.append(
      createTextElement("div", "finding-title", finding.title),
      createTextElement("span", "finding-rule", finding.rule_id),
    );
    const location = document.createElement("div");
    location.className = "finding-location";
    location.append(
      document.createTextNode(finding.path),
      document.createElement("br"),
      createTextElement("span", "", `Line ${finding.line}`),
    );
    const recommendation = createTextElement(
      "div",
      "finding-recommendation",
      finding.recommendation,
    );
    row.append(severity, details, location, recommendation);
    return row;
  }

  function renderFindings() {
    elements.findingsList.replaceChildren();
    const visibleFindings = findings.filter(matchesFilters);
    elements.visibleCount.textContent = `${visibleFindings.length} finding${visibleFindings.length === 1 ? "" : "s"}`;
    elements.footerShowing.textContent = String(visibleFindings.length);

    if (visibleFindings.length === 0) {
      if (findings.length === 0) {
        elements.emptyTitle.textContent = scanSummary
          ? "Looking good — no findings"
          : "Your security review starts here";
        elements.emptyCopy.textContent = scanSummary
          ? "No matching risks were found in the scanned files."
          : "Choose a project above to check for common vulnerabilities.";
      } else {
        elements.emptyTitle.textContent = "No matching findings";
        elements.emptyCopy.textContent = "Try adjusting the search or severity filter.";
      }
      elements.findingsList.append(elements.emptyState);
      return;
    }

    visibleFindings.forEach((finding) => elements.findingsList.append(renderFinding(finding)));
  }

  function showWarnings(warnings) {
    elements.warnings.replaceChildren();
    elements.warnings.hidden = warnings.length === 0;
    if (warnings.length === 0) return;
    elements.warnings.append(createTextElement("strong", "", "Some files could not be scanned:"));
    const list = document.createElement("ul");
    warnings.slice(0, 20).forEach((warning) => {
      list.append(createTextElement("li", "", warning));
    });
    if (warnings.length > 20) {
      list.append(createTextElement("li", "", `And ${warnings.length - 20} more file(s).`));
    }
    elements.warnings.append(list);
  }

  function detectFindings(content, path) {
    const matches = [];
    const lines = content.split(/\r?\n/);
    lines.forEach((line, index) => {
      for (const rule of rules) {
        if (!rule.pattern.test(line)) continue;
        if (rule.safePattern?.test(line)) continue;
        matches.push({
          rule_id: rule.id,
          severity: rule.severity,
          title: rule.title,
          path,
          line: index + 1,
          recommendation: rule.recommendation,
        });
      }
    });
    return matches;
  }

  function yieldToBrowser() {
    return new Promise((resolve) => window.setTimeout(resolve, 0));
  }

  async function scanFiles(fileList) {
    if (scanning) return;
    scanning = true;
    window.clearTimeout(progressHideTimer);
    elements.fileInput.value = "";
    elements.folderInput.value = "";
    findings = [];
    scanSummary = null;
    elements.warnings.hidden = true;
    elements.exportButton.disabled = true;
    elements.totalFindings.textContent = "—";
    elements.urgentFindings.textContent = "—";
    elements.filesScanned.textContent = "—";
    elements.findingsFoot.textContent = "Scanning selected files...";
    elements.scanStatus.replaceChildren();
    const statusDot = document.createElement("span");
    statusDot.className = "status-dot";
    elements.scanStatus.append(statusDot, document.createTextNode(" Scanning"));
    elements.scanTime.textContent = "Please wait";
    elements.progress.hidden = false;
    showMessage("");
    renderFindings();

    const startTime = performance.now();
    const eligibleFiles = Array.from(fileList).filter((file) => {
      const path = displayPath(file);
      return isScannable(file) && !isIgnoredPath(path);
    });
    const warnings = [];
    const scanableFiles = [];
    let filesScanned = 0;

    eligibleFiles.forEach((file) => {
      if (file.size > MAX_FILE_SIZE) {
        warnings.push(`${displayPath(file)}: skipped (larger than 1 MB)`);
      } else {
        scanableFiles.push(file);
      }
    });

    if (scanableFiles.length === 0) {
      scanning = false;
      elements.progress.hidden = true;
      elements.filesScanned.textContent = "0";
      elements.totalFindings.textContent = "0";
      elements.urgentFindings.textContent = "0";
      elements.findingsFoot.textContent = "No supported files were selected";
      elements.scanStatus.replaceChildren();
      const idleDot = document.createElement("span");
      idleDot.className = "status-dot status-dot-idle";
      elements.scanStatus.append(idleDot, document.createTextNode(" Ready"));
      elements.scanTime.textContent = "Choose source or config files to scan";
      showWarnings(warnings);
      showMessage(
        eligibleFiles.length === 0
          ? "No supported source or configuration files found. Choose code files or a project folder."
          : "All supported files exceeded the 1 MB per-file size limit.",
        eligibleFiles.length === 0 && warnings.length === 0,
      );
      elements.progress.hidden = true;
      return;
    }

    try {
      for (let index = 0; index < scanableFiles.length; index += 1) {
        const file = scanableFiles[index];
        updateProgress(index, scanableFiles.length, `Scanning ${displayPath(file)}`);
        try {
          const content = await file.text();
          if (content.includes("\0")) {
            warnings.push(`${displayPath(file)}: skipped (binary file)`);
          } else {
            findings.push(...detectFindings(content, displayPath(file)));
            filesScanned += 1;
          }
        } catch {
          warnings.push(`${displayPath(file)}: could not read this file`);
        }
        updateProgress(index + 1, scanableFiles.length, `Scanned ${displayPath(file)}`);
        if (index < scanableFiles.length - 1) await yieldToBrowser();
      }
      findings.sort(
        (left, right) =>
          severityOrder[left.severity] - severityOrder[right.severity]
          || left.path.localeCompare(right.path)
          || left.line - right.line,
      );
      const elapsed = (performance.now() - startTime) / 1000;
      scanSummary = {
        filesScanned,
        duration: elapsed < 1 ? "Finished in less than a second" : `Finished in ${elapsed.toFixed(1)} seconds`,
      };
      updateMetrics();
      showWarnings(warnings);
      renderFindings();
      updateProgress(scanableFiles.length, scanableFiles.length, "Security scan complete");
      progressHideTimer = window.setTimeout(() => {
        elements.progress.hidden = true;
      }, 1600);
    } catch {
      scanning = false;
      elements.progress.hidden = true;
      showMessage("The scan could not be completed. Try selecting the files again.", true);
      return;
    }
    scanning = false;
  }

  function exportReport() {
    if (!scanSummary) return;
    const report = {
      scanner: "Sentinel browser scanner",
      generated_at: new Date().toISOString(),
      files_scanned: scanSummary.filesScanned,
      finding_count: findings.length,
      findings,
      scan_warnings: Array.from(elements.warnings.querySelectorAll("li"), (item) => item.textContent),
      note: "Heuristic static checks only. Review findings; no source lines or secret values are included.",
    };
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
    );
    const download = document.createElement("a");
    download.href = url;
    download.download = "sentinel-security-report.json";
    document.body.append(download);
    download.click();
    download.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  elements.chooseFiles.addEventListener("click", () => elements.fileInput.click());
  elements.chooseFolder.addEventListener("click", () => elements.folderInput.click());
  elements.newScan.addEventListener("click", () => {
    document.querySelector("#scan-heading").scrollIntoView({ behavior: "smooth", block: "center" });
    elements.fileInput.click();
  });
  elements.fileInput.addEventListener("change", () => {
    if (elements.fileInput.files.length) scanFiles(elements.fileInput.files);
  });
  elements.folderInput.addEventListener("change", () => {
    if (elements.folderInput.files.length) scanFiles(elements.folderInput.files);
  });
  ["dragenter", "dragover"].forEach((eventName) => {
    elements.dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      elements.dropZone.classList.add("is-dragging");
    });
  });
  ["dragleave", "drop"].forEach((eventName) => {
    elements.dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      elements.dropZone.classList.remove("is-dragging");
    });
  });
  elements.dropZone.addEventListener("drop", (event) => {
    if (event.dataTransfer?.files.length) scanFiles(event.dataTransfer.files);
  });
  elements.search.addEventListener("input", renderFindings);
  elements.severityFilter.addEventListener("change", renderFindings);
  elements.exportButton.addEventListener("click", exportReport);
  apiElements.discoverHosts.addEventListener("click", discoverPrivateHosts);
  apiElements.chooseVirusFiles.addEventListener("click", () => apiElements.virusFileInput.click());
  apiElements.virusFileInput.addEventListener("change", () => scanWithDefender(apiElements.virusFileInput.files));
  apiElements.webCheckForm.addEventListener("submit", checkPrivateWebService);
  apiElements.logFileInput.addEventListener("change", () => analyzeLogFiles(apiElements.logFileInput.files));
  loadDefenderStatus();
})();

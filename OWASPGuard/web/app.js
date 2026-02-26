let allFindings = [];

const elements = {
  form: document.getElementById("scan-form"),
  projectPath: document.getElementById("project-path"),
  langPython: document.getElementById("lang-python"),
  langJs: document.getElementById("lang-js"),
  maxWorkers: document.getElementById("max-workers"),
  onlineCve: document.getElementById("online-cve"),
  scanButton: document.getElementById("scan-button"),
  scanStatus: document.getElementById("scan-status"),
  filterSeverity: document.getElementById("filter-severity"),
  filterOwasp: document.getElementById("filter-owasp"),
  searchText: document.getElementById("search-text"),
  summaryTotal: document.getElementById("summary-total"),
  summaryCritical: document.getElementById("summary-critical"),
  summaryHigh: document.getElementById("summary-high"),
  summaryMedium: document.getElementById("summary-medium"),
  summaryLow: document.getElementById("summary-low"),
  statFiles: document.getElementById("stat-files"),
  statDuration: document.getElementById("stat-duration"),
  statProject: document.getElementById("stat-project"),
  tableCaption: document.getElementById("table-caption"),
  tableBody: document.querySelector("#findings-table tbody"),
  details: document.getElementById("details"),
};

function setScanStatus(text) {
  elements.scanStatus.textContent = text;
}

function setLoading(isLoading) {
  elements.scanButton.disabled = isLoading;
  if (isLoading) {
    setScanStatus("Running scan… this may take several minutes for large projects.");
  } else {
    setScanStatus("Idle");
  }
}

function summarizeFindings(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    const sev = (f.severity || "INFO").toUpperCase();
    if (counts[sev] !== undefined) counts[sev] += 1;
  }
  elements.summaryTotal.textContent = findings.length;
  elements.summaryCritical.textContent = counts.CRITICAL;
  elements.summaryHigh.textContent = counts.HIGH;
  elements.summaryMedium.textContent = counts.MEDIUM;
  elements.summaryLow.textContent = counts.LOW;
}

function applyFilters() {
  const severityFilter = elements.filterSeverity.value;
  const owaspFilter = elements.filterOwasp.value;
  const search = elements.searchText.value.trim().toLowerCase();

  const filtered = allFindings.filter((f) => {
    const sev = (f.severity || "").toUpperCase();
    const owasp = (f.owasp_category || "").toUpperCase();
    const file = (f.file_path || "").toLowerCase();
    const desc = (f.description || "").toLowerCase();

    if (severityFilter !== "ALL" && sev !== severityFilter) return false;
    if (owaspFilter !== "ALL" && owasp !== owaspFilter) return false;
    if (search && !file.includes(search) && !desc.includes(search)) return false;
    return true;
  });

  renderTable(filtered);
}

function renderTable(findings) {
  elements.tableBody.innerHTML = "";
  elements.tableCaption.textContent =
    findings.length === 0
      ? "No findings match the current filters."
      : `${findings.length} findings shown`;

  findings.forEach((f, index) => {
    const tr = document.createElement("tr");
    tr.dataset.index = String(index);

    const sev = f.severity || "N/A";
    const owasp = f.owasp_category || "N/A";
    const file = (f.file_path || "").split(/[\\/]/).pop() || "N/A";
    const line = f.line_number ?? "N/A";
    const desc = f.description || "";
    const shortDesc = desc.length > 100 ? desc.slice(0, 100) + "…" : desc;

    tr.innerHTML = `
      <td>${sev}</td>
      <td>${owasp}</td>
      <td>${file}</td>
      <td>${line}</td>
      <td>${shortDesc}</td>
    `;

    tr.addEventListener("click", () => {
      document
        .querySelectorAll("#findings-table tbody tr")
        .forEach((row) => row.classList.remove("selected"));
      tr.classList.add("selected");
      showDetails(f);
    });

    elements.tableBody.appendChild(tr);
  });
}

function showDetails(finding) {
  let details = "";
  details += `Description:\n${finding.description || "N/A"}\n\n`;
  details += `Severity: ${finding.severity || "N/A"} (Score: ${
    finding.severity_score ?? "N/A"
  })\n`;

  if (finding.ml_confidence !== undefined) {
    try {
      const ml = Math.max(0, Math.min(1, Number(finding.ml_confidence)));
      if (!Number.isNaN(ml)) {
        details += `ML confidence: ${(ml * 100).toFixed(1)}%\n`;
      }
    } catch {
      // ignore
    }
  }

  details += `OWASP: ${
    finding.owasp_category_full || finding.owasp_category || "N/A"
  }\n`;
  details += `File: ${finding.file_path || "N/A"}\n`;
  details += `Line: ${finding.line_number ?? "N/A"}\n`;
  details += `Rule ID: ${finding.rule_id || "N/A"}\n`;
  details += `Scan type: ${finding.scan_type || "SAST"}\n\n`;

  const codeSnippet = finding.code_snippet || finding.line_content;
  if (codeSnippet) {
    details += "Code:\n";
    details += `${codeSnippet}\n\n`;
  }

  if (finding.cve_id) {
    details += `CVE: ${finding.cve_id}\n`;
    if (finding.package) details += `Package: ${finding.package}\n`;
    if (finding.version) details += `Version: ${finding.version}\n`;
    details += "\n";
  }

  if (finding.remediation) {
    details += `Remediation:\n${finding.remediation}\n\n`;
  } else if (finding.recommendation) {
    details += `Recommendation:\n${finding.recommendation}\n\n`;
  }

  if (finding.confidence) {
    details += `Confidence label: ${finding.confidence}\n`;
  }
  if (finding.exploitability) {
    details += `Exploitability: ${finding.exploitability}\n`;
  }

  elements.details.textContent = details;
}

elements.form.addEventListener("submit", async (evt) => {
  evt.preventDefault();

  const projectPath = elements.projectPath.value.trim();
  const languages = [];
  if (elements.langPython.checked) languages.push("python");
  if (elements.langJs.checked) languages.push("javascript");

  if (!projectPath) {
    alert("Please enter a project path.");
    return;
  }
  if (languages.length === 0) {
    alert("Please select at least one language.");
    return;
  }

  const maxWorkers = Number(elements.maxWorkers.value) || 4;
  const useOnlineCve = elements.onlineCve.checked;

  const payload = {
    project_path: projectPath,
    languages,
    max_workers: maxWorkers,
    use_online_cve: useOnlineCve,
  };

  setLoading(true);
  elements.tableBody.innerHTML = "";
  elements.details.textContent = "Scan running…";

  try {
    const resp = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!resp.ok) {
      const errorText = await resp.text();
      throw new Error(errorText || `Scan failed with status ${resp.status}`);
    }

    const data = await resp.json();
    allFindings = data.findings || [];

    summarizeFindings(allFindings);

    const stats = data.stats || {};
    elements.statFiles.textContent = stats.files_scanned ?? 0;
    elements.statDuration.textContent = (stats.scan_duration ?? 0).toFixed(2);
    elements.statProject.textContent = projectPath;

    elements.tableCaption.textContent = `${allFindings.length} findings loaded`;
    applyFilters();
    setScanStatus("Scan complete.");
  } catch (err) {
    console.error(err);
    setScanStatus("Error running scan.");
    elements.details.textContent = `Error:\n${String(err)}`;
  } finally {
    setLoading(false);
  }
});

elements.filterSeverity.addEventListener("change", applyFilters);
elements.filterOwasp.addEventListener("change", applyFilters);
elements.searchText.addEventListener("input", () => {
  // Light debounce
  window.clearTimeout(window.__owaspguard_search_timeout);
  window.__owaspguard_search_timeout = window.setTimeout(applyFilters, 150);
});


const API_URL =
  window.location.port === "5000"
    ? ""
    : (window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost" || window.location.protocol === "file:")
      ? "http://127.0.0.1:5000"
      : window.location.origin;

const storedUser = localStorage.getItem("securepersona_user");
let currentUser = null;

try {
  currentUser = storedUser ? JSON.parse(storedUser) : null;
} catch {
  currentUser = null;
}

if (!currentUser || !currentUser.id) {
  window.location.href = "login.html";
}

const $ = (id) => document.getElementById(id);

// ---------- Utility functions ----------

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[character]);
}

function showMessage(element, text, type = "error") {
  if (!element) return;

  element.textContent = text;
  element.className = `message show ${type}`;
}

function decisionClass(decision) {
  switch (String(decision || "").toUpperCase()) {
    case "BLOCK":
      return "decision-block";
    case "ANONYMIZE":
      return "decision-anonymize";
    default:
      return "decision-allow";
  }
}

async function apiFetch(path, options = {}) {
  let response;

  try {
    response = await fetch(`${API_URL}${path}`, options);
  } catch {
    throw new Error(
      "Cannot connect to SecurePersona AI. Make sure Python Flask is running on http://127.0.0.1:5000 (run 'python app.py')."
    );
  }

  const responseText = await response.text();
  let result;

  try {
    result = responseText ? JSON.parse(responseText) : {};
  } catch {
    throw new Error(
      `The server returned an invalid response (HTTP ${response.status}).`
    );
  }

  if (!response.ok || result.success === false) {
    throw new Error(
      result.message || `Request failed with HTTP ${response.status}.`
    );
  }

  return result;
}

function userRequestBody(extra = {}) {
  return {
    user_id: currentUser.id,
    ...extra
  };
}

// ---------- Normalize API response ----------

function normalizeAnalysis(response) {
  let result =
    response?.analysis ??
    response?.result ??
    response?.data ??
    response;

  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("The server did not return a valid analysis result.");
  }

  if (result.analysis && typeof result.analysis === "object") {
    result = result.analysis;
  }

  const requiredFields = ["decision", "risk_score", "risk_level"];

  const missingFields = requiredFields.filter(
    (field) => result[field] === undefined || result[field] === null
  );

  if (missingFields.length) {
    throw new Error(
      "The server response is missing: " +
      missingFields.join(", ") +
      ". Check the response from /api/analyze."
    );
  }

  return result;
}

function normalizeDetectedData(items) {
  if (!Array.isArray(items)) return [];

  return items.map((item) => {
    if (typeof item === "string") return item;

    if (item && typeof item === "object") {
      const name = item.type || item.name || item.label || "Sensitive data";
      const count = Number(item.count || 0);

      return count > 1 ? `${name} (${count} matches)` : name;
    }

    return String(item);
  });
}

function normalizeReasons(reasons) {
  if (!Array.isArray(reasons)) return [];

  return reasons.map((reason) => {
    if (typeof reason === "string") return reason;

    if (reason && typeof reason === "object") {
      return reason.message || reason.reason || JSON.stringify(reason);
    }

    return String(reason);
  });
}

// ---------- Render analysis result ----------

function renderAnalysis(response, targetId = "analysisResult") {
  const result = normalizeAnalysis(response);
  const decision = String(result.decision).toUpperCase();

  const riskScore = Math.min(
    100,
    Math.max(0, Number(result.risk_score) || 0)
  );

  const detectedData = normalizeDetectedData(result.detected_data);
  const reasons = normalizeReasons(result.reasons);

  if (targetId === "analysisResult") {
    const panel = $("analysisResult");

    if (!panel) {
      throw new Error(
        "The analysis result panel is missing from dashboard.html."
      );
    }

    const detectedHtml = detectedData.length
      ? detectedData
          .map(
            (type) => `<span class="chip">${escapeHTML(type)}</span>`
          )
          .join("")
      : '<span class="muted">No configured sensitive-data patterns detected.</span>';

    const reasonsHtml = reasons.length
      ? reasons
          .map((reason) => `<li>${escapeHTML(reason)}</li>`)
          .join("")
      : "<li>No explanation was returned by the server.</li>";

    const trustScoreDisplay = result.trust_score !== undefined
      ? `${Number(result.trust_score) || 0}/100`
      : "Not provided";

    const protectedText = escapeHTML(
      result.protected_content ?? "No protected-content preview was returned."
    );

    const dlpActionText = escapeHTML(
      result.dlp_action || result.action_description || ""
    );

    panel.innerHTML = `
      <div class="result-header">
        <div>
          <span class="eyebrow">ANALYSIS RESULT</span>
          <h2 id="decisionTitle">${escapeHTML(decision)}</h2>
        </div>
        <span id="decisionTag" class="tag ${decisionClass(decision)}">
          ${escapeHTML(String(result.risk_level).toUpperCase())} RISK
        </span>
      </div>

      <div class="result-metrics">
        <div>
          <small>RISK SCORE</small>
          <strong id="riskScore">${riskScore}/100</strong>
          <div class="meter"><span id="riskMeter" style="width: ${riskScore}%"></span></div>
        </div>
        <div>
          <small>SECURITY PERSONA</small>
          <strong id="personaResult">${escapeHTML(result.persona || "Not provided")}</strong>
        </div>
        <div>
          <small>TRUST SCORE</small>
          <strong id="trustScore">${trustScoreDisplay}</strong>
        </div>
      </div>

      <h3>Detected sensitive data</h3>
      <div id="detectedData" class="chip-list">
        ${detectedHtml}
      </div>

      <h3>Why was this decision made?</h3>
      <ul id="reasonList" class="reason-list">
        ${reasonsHtml}
      </ul>

      <h3>Protected content</h3>
      <pre id="protectedContent" class="protected-content">${protectedText}</pre>
      <p id="dlpAction" class="muted">${dlpActionText}</p>
    `;

    // Reveal the result after all fields have been updated.
    panel.hidden = false;

    return result;
  }

  // What-If Simulator result
  const container = $(targetId);

  if (!container) {
    throw new Error("The simulator result container is missing.");
  }

  container.innerHTML = `
    <div class="simulation-card">
      <span class="tag ${decisionClass(decision)}">
        ${escapeHTML(decision)}
      </span>

      <h3>Risk score: ${riskScore}/100</h3>
      <p>Persona: ${escapeHTML(result.persona || "Not provided")}</p>
      <p>Risk level: ${escapeHTML(result.risk_level)}</p>
      <p>${escapeHTML(result.dlp_action || result.action_description || "")}</p>

      <strong>Detected sensitive data</strong>
      <div class="chip-list">
        ${
          detectedData.length
            ? detectedData
                .map(
                  (item) =>
                    `<span class="chip">${escapeHTML(item)}</span>`
                )
                .join("")
            : '<span class="muted">No configured patterns detected.</span>'
        }
      </div>

      <strong>Decision factors</strong>
      <ul class="reason-list">
        ${
          reasons.length
            ? reasons
                .map((reason) => `<li>${escapeHTML(reason)}</li>`)
                .join("")
            : "<li>No explanation was returned.</li>"
        }
      </ul>
    </div>
  `;

  return result;
}

// ---------- Show analysis errors ----------

function showAnalysisError(error) {
  const panel = $("analysisResult");

  if (!panel) return;

  panel.innerHTML = `
    <div class="result-header">
      <div>
        <span class="eyebrow">ANALYSIS ERROR</span>
        <h2>Could not display the result</h2>
      </div>
    </div>

    <p class="error-text">${escapeHTML(error.message)}</p>

    <p class="muted">
      Check the Python backend terminal and browser Console for details.
    </p>
  `;

  panel.hidden = false;
}

// ---------- User information and logout ----------

if ($("userName")) {
  $("userName").textContent = currentUser.name || currentUser.email;
}

if ($("welcomeName")) {
  $("welcomeName").textContent = currentUser.name || "User";
}

$("logoutButton")?.addEventListener("click", () => {
  localStorage.removeItem("securepersona_user");
  window.location.href = "login.html";
});

// ---------- Main Security Analyzer ----------

$("analysisForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();

  const button = $("analyzeButton");
  const message = $("analysisMessage");
  const panel = $("analysisResult");

  const content = $("content").value.trim();

  if (!content) {
    showMessage(message, "Please enter sample content to analyze.");
    $("content").focus();
    return;
  }

  button.disabled = true;
  button.textContent = "Analyzing...";
  message.className = "message";

  // Hide only the previous result while the new analysis runs.
  panel.hidden = true;

  const data = userRequestBody({
    source: $("source").value,
    action: $("action").value,
    destination: $("destination").value,
    content
  });

  try {
    // 1. Send the analysis request.
    const response = await apiFetch("/api/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(data)
    });

    // 2. Render and show the new result immediately.
    renderAnalysis(response);

    panel.hidden = false;

    showMessage(
      message,
      "Analysis completed successfully. Your result is displayed below.",
      "success"
    );

    // 3. Scroll to the result.
    panel.scrollIntoView({
      behavior: "smooth",
      block: "start"
    });

    // 4. Refresh history and alerts independently.
    // These requests must not delay or hide the displayed result.
    refreshDashboard().catch((error) => {
      console.error("Dashboard refresh failed:", error);
    });

  } catch (error) {
    showMessage(message, error.message);
    showAnalysisError(error);

    console.error("SecurePersona analysis failed:", error);

  } finally {
    button.disabled = false;
    button.textContent = "Analyze activity →";
  }
});

// ---------- What-If Simulator ----------

$("simulationForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();

  const container = $("simulationResult");
  const button = event.submitter;
  const content = $("simContent").value.trim();

  if (!content) {
    container.textContent =
      "Please enter sample content to simulate.";

    $("simContent").focus();
    return;
  }

  if (button) {
    button.disabled = true;
    button.textContent = "Simulating...";
  }

  container.textContent = "Running scenario...";

  try {
    const response = await apiFetch("/api/simulate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(
        userRequestBody({
          source: "What-If Simulator",
          action: $("simAction").value,
          destination: $("simDestination").value,
          content
        })
      )
    });

    renderAnalysis(response, "simulationResult");

    container.scrollIntoView({
      behavior: "smooth",
      block: "nearest"
    });

  } catch (error) {
    container.textContent = `Simulation failed: ${error.message}`;

    console.error("SecurePersona simulation failed:", error);

  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = "Simulate scenario";
    }
  }
});

// ---------- Analysis History ----------

async function loadHistory() {
  const body = $("historyBody");
  if (!body) return [];

  body.innerHTML =
    '<tr><td colspan="4">Loading history...</td></tr>';

  try {
    const response = await apiFetch(
      `/api/history?user_id=${encodeURIComponent(currentUser.id)}`
    );

    const history = response.history || [];

    if (!history.length) {
      body.innerHTML =
        '<tr><td colspan="4">No analyses yet. Run your first analysis above.</td></tr>';

      return history;
    }

    body.innerHTML = history.map((item) => `
      <tr>
        <td>${escapeHTML(item.created_at)}</td>
        <td>${escapeHTML(item.persona || "Not provided")}</td>
        <td>${escapeHTML(item.risk_score)}/100</td>
        <td>
          <span class="decision-pill ${decisionClass(item.decision)}">
            ${escapeHTML(item.decision)}
          </span>
        </td>
      </tr>
    `).join("");

    return history;

  } catch (error) {
    body.innerHTML = `
      <tr>
        <td colspan="4">${escapeHTML(error.message)}</td>
      </tr>
    `;

    console.error("History loading failed:", error);

    return [];
  }
}

// ---------- Security Alerts ----------

async function loadAlerts() {
  const container = $("alertsList");
  if (!container) return;

  container.textContent = "Loading alerts...";

  try {
    const response = await apiFetch(
      `/api/alerts?user_id=${encodeURIComponent(currentUser.id)}`
    );

    const alerts = response.alerts || [];

    const openAlertsEl = $("openAlerts");
    if (openAlertsEl) {
      openAlertsEl.textContent =
        alerts.filter((alert) => !alert.is_read).length;
    }

    if (!alerts.length) {
      container.textContent =
        "No alerts yet. Security alerts will appear here when generated.";

      return;
    }

    container.innerHTML = alerts.map((alert) => `
      <article class="alert-item">
        <div>
          <strong>${escapeHTML(alert.title)}</strong>
          <p>${escapeHTML(alert.message)}</p>
          <small>
            ${escapeHTML(alert.created_at)} ·
            ${escapeHTML(alert.severity)} risk
          </small>
        </div>

        ${
          alert.is_read
            ? '<span class="tag tag-green">READ</span>'
            : `
              <button
                class="btn btn-secondary mark-read"
                data-alert-id="${Number(alert.id)}"
                type="button">
                Mark read
              </button>
            `
        }
      </article>
    `).join("");

    container.querySelectorAll(".mark-read").forEach((button) => {
      button.addEventListener("click", async () => {
        button.disabled = true;

        try {
          await apiFetch(
            `/api/alerts/${button.dataset.alertId}/read`,
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json"
              },
              body: JSON.stringify(userRequestBody())
            }
          );

          await loadAlerts();

        } catch (error) {
          button.disabled = false;
          alert(error.message);
        }
      });
    });

  } catch (error) {
    container.textContent = error.message;

    console.error("Alerts loading failed:", error);
  }
}

// ---------- Dashboard Statistics ----------

async function refreshDashboard() {
  const history = await loadHistory();

  const totalEl = $("totalAnalyses");
  if (totalEl) totalEl.textContent = history.length;

  const highRiskEl = $("highRiskCount");
  if (highRiskEl) {
    highRiskEl.textContent = history.filter(
      (item) => Number(item.risk_score) >= 60
    ).length;
  }

  const blockedEl = $("blockedCount");
  if (blockedEl) {
    blockedEl.textContent = history.filter(
      (item) => String(item.decision).toUpperCase() === "BLOCK"
    ).length;
  }

  await loadAlerts();
}

$("refreshButton")?.addEventListener("click", () => {
  refreshDashboard().catch((error) => {
    console.error("Dashboard refresh failed:", error);
  });
});

// ---------- Initial Dashboard Load ----------

refreshDashboard().catch((error) => {
  console.error("Initial dashboard loading failed:", error);
});

const API_URL =
  window.location.port === "5000"
    ? ""
    : (window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost" || window.location.protocol === "file:")
      ? "http://127.0.0.1:5000"
      : window.location.origin;

const loginForm = document.getElementById("loginForm");
const messageBox = document.getElementById("message");
const loginButton = document.getElementById("loginButton");

function showLoginMessage(message, type = "error") {
  messageBox.textContent = message;
  messageBox.className = `message show ${type}`;
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;

  loginButton.disabled = true;
  loginButton.textContent = "Verifying…";

  try {
    const response = await fetch(`${API_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const result = await response.json();

    if (!response.ok || !result.success) {
      showLoginMessage(result.message || "Login failed.");
      return;
    }

    localStorage.setItem("securepersona_user", JSON.stringify(result.user));
    showLoginMessage("Login successful. Opening your dashboard…", "success");

    setTimeout(() => {
      window.location.href = "dashboard.html";
    }, 500);
  } catch (error) {
    showLoginMessage(
      "Cannot reach the backend. Make sure Python Flask is running on http://127.0.0.1:5000 (run 'python app.py')."
    );
    console.error("Login request failed:", error);
  } finally {
    loginButton.disabled = false;
    loginButton.textContent = "Log in securely →";
  }
});
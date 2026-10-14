const API_URL =
  window.location.port === "5000"
    ? ""
    : (window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost" || window.location.protocol === "file:")
      ? "http://127.0.0.1:5000"
      : window.location.origin;

const signupForm = document.getElementById("signupForm");
const messageBox = document.getElementById("message");
const signupButton = document.getElementById("signupButton");

function showSignupMessage(message, type = "error") {
  messageBox.textContent = message;
  messageBox.className = `message show ${type}`;
}

signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const name = document.getElementById("full_name").value.trim();
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirm_password").value;
  const termsAccepted = document.getElementById("terms").checked;

  if (!name || !email || !password || !confirmPassword) {
    showSignupMessage("Please complete all fields.");
    return;
  }

  if (password.length < 8) {
    showSignupMessage("Your password must contain at least 8 characters.");
    return;
  }

  if (password !== confirmPassword) {
    showSignupMessage("The passwords do not match.");
    return;
  }

  if (!termsAccepted) {
    showSignupMessage("Please tick the agreement checkbox to continue.");
    return;
  }

  signupButton.disabled = true;
  signupButton.textContent = "Creating account…";

  try {
    const response = await fetch(`${API_URL}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, email, password })
    });

    const result = await response.json();

    if (!response.ok || !result.success) {
      showSignupMessage(result.message || "Could not create your account.");
      return;
    }

    showSignupMessage("Account created. Redirecting to login…", "success");
    setTimeout(() => {
      window.location.href = "login.html";
    }, 900);
  } catch (error) {
    showSignupMessage(
      "Cannot reach the backend. Make sure Python Flask is running on http://127.0.0.1:5000 (run 'python app.py')."
    );
    console.error("Signup request failed:", error);
  } finally {
    signupButton.disabled = false;
    signupButton.textContent = "Create account →";
  }
});
const VALID_BACKUP_CODES = [
  "615553793183",
  "941942329520",
  "076814800653",
  "005048598496"
];

// Security keys
const DEACTIVATE_KEY = "123456";
const ACTIVATE_KEY = "654321";

// Global variables for NFC auth
let USER_AES_KEY = "";
let USER_EXPECTED_TEXT = "";
let USER_ALLOWED_SERIAL = "";
let CURRENT_USERNAME = "";

// USER LOGIN
document.getElementById("loginForm")?.addEventListener("submit", async function (e) {
  e.preventDefault();

  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  if (!username || !password) {
    alert("Please enter both username and password");
    return;
  }

  try {
    const res = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    const data = await res.json();
    
    if (!res.ok) {
      throw new Error(data.message || "Login failed");
    }

    alert(data.message);

    if (data.message === "Login successful") {
      USER_AES_KEY = data.aesKey;
      USER_EXPECTED_TEXT = data.expectedText;
      USER_ALLOWED_SERIAL = data.allowedSerial;
      CURRENT_USERNAME = data.username;
      showNFCAuth();
    }
  } catch (error) {
    console.error("Login error:", error);
    alert(error.message);
  }
});

// MANAGER LOGIN
document.getElementById("managerLoginForm")?.addEventListener("submit", async function (e) {
  e.preventDefault();

  const username = document.getElementById("managerIdentifier").value;
  const password = document.getElementById("managerPassword").value;

  if (!username || !password) {
    alert("Please enter both username and password");
    return;
  }

  try {
    const res = await fetch("/manager-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    const data = await res.json();
    
    if (!res.ok) {
      throw new Error(data.message || "Login failed");
    }

    alert(data.message);

    if (data.message === "Login successful") {
      USER_AES_KEY = data.aesKey;
      USER_EXPECTED_TEXT = data.expectedText;
      USER_ALLOWED_SERIAL = data.allowedSerial;
      CURRENT_USERNAME = data.username;
      showNFCAuth();
    }
  } catch (error) {
    console.error("Manager login error:", error);
    alert(error.message);
  }
});

// Show NFC auth overlay and trigger scan
async function showNFCAuth() {
  const overlay = document.getElementById("nfcAuthOverlay");
  if (!overlay) return;
  
  overlay.style.display = "flex";
  setTimeout(scanNFC, 500);
}

async function scanNFC() {
  const statusEl = document.getElementById("nfcStatus");
  const scanBtn = document.getElementById("nfcScanBtn");

  if (!statusEl || !scanBtn) return;

  statusEl.textContent = "Preparing scanner...";
  scanBtn.disabled = true;

  if (!("NDEFReader" in window)) {
    statusEl.textContent = "NFC not supported on this device.";
    scanBtn.disabled = false;
    return;
  }

  try {
    const reader = new NDEFReader();
    await reader.scan();
    statusEl.textContent = "Ready - Tap your Ring now";

    reader.onreading = (event) => {
      statusEl.textContent = "Reading Ring...";

      // Play beep sound if available
      const beep = document.getElementById("beep");
      if (beep) {
        beep.play().catch((e) => console.warn("Sound failed:", e));
      }

      const serialNumber = event.serialNumber
        ? formatSerialNumber(event.serialNumber)
        : null;

      if (!serialNumber) {
        statusEl.textContent = "⚠️ Serial number not detected. Try a different phone.";
        scanBtn.disabled = false;
        return;
      }

      const decoder = new TextDecoder();
      let encryptedData = null;

      for (const record of event.message.records) {
        try {
          encryptedData = decoder.decode(record.data).trim();
          break;
        } catch (err) {
          console.error("Error reading record:", err);
        }
      }

      if (encryptedData) {
        processNFCCard(encryptedData, serialNumber);
      } else {
        statusEl.textContent = "Error: No valid data on NFC ring";
        scanBtn.disabled = false;
      }
    };

    reader.onreadingerror = () => {
      statusEl.textContent = "Error: Couldn't read NFC ring";
      scanBtn.disabled = false;
    };
  } catch (err) {
    console.error("NFC error:", err);
    statusEl.textContent = "NFC error: " + err.message;
    scanBtn.disabled = false;
  }
}

function formatSerialNumber(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(":")
    .toUpperCase();
}

function normalizeSerialNumber(serial) {
  return serial ? serial.replace(/:/g, "").toUpperCase() : "";
}

async function processNFCCard(encryptedBase64, serialNumber) {
  const statusEl = document.getElementById("nfcStatus");
  const scanBtn = document.getElementById("nfcScanBtn");

  if (!statusEl || !scanBtn) return;

  const normalizedSerial = normalizeSerialNumber(serialNumber);
  const normalizedAllowed = normalizeSerialNumber(USER_ALLOWED_SERIAL);

  if (normalizedSerial !== normalizedAllowed) {
    statusEl.textContent = `❌ Access Denied: Invalid card (Serial: ${serialNumber || 'unknown'})`;
    scanBtn.disabled = false;
    return;
  }

try {
  // Send to server for verification
  const res = await fetch("/api/nfc-auth", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      encryptedData: encryptedBase64,
      serial: serialNumber,
      username: CURRENT_USERNAME,
      isManager: false // Set appropriately based on user type
    })
  });

  const data = await res.json();

  if (!res.ok) {
    console.error("Server response not OK:", data);
    throw new Error(data.message || "Authentication failed");
  }

  if (data.success) {
    statusEl.innerHTML = "✅ Authentication successful!<br>Redirecting...";
    setTimeout(() => {
      window.location.href = "home.html";
    }, 1000);
  } else {
    console.warn("Authentication rejected:", data);
    statusEl.textContent = data.message || "Authentication failed";
    scanBtn.disabled = false;
  }

} catch (err) {
  console.error("Authentication error:", err);

  // Show debug data on the page for easy testing
  statusEl.innerHTML = `
    ❌ Security verification failed<br>
    <strong>Error:</strong> ${err.message}<br>
    <strong>Encrypted Data:</strong> ${encryptedBase64}<br>
    <strong>Serial:</strong> ${serialNumber}<br>
    <strong>Username:</strong> ${CURRENT_USERNAME}
  `;

  scanBtn.disabled = false;
}


// Back button functionality
document.getElementById("backButton")?.addEventListener("click", function() {
  const overlay = document.getElementById("nfcAuthOverlay");
  if (overlay) overlay.style.display = "none";
});

// NFC scan button
document.getElementById("nfcScanBtn")?.addEventListener("click", scanNFC);

// Backup code button
document.getElementById("backupCodeBtn")?.addEventListener("click", function() {
  const overlay = document.getElementById("nfcAuthOverlay");
  const modal = document.getElementById("backupCodeModal");
  
  if (overlay) overlay.style.display = "none";
  if (modal) modal.style.display = "flex";
  
  // Auto-focus first input
  const input = document.getElementById("backupCode1");
  if (input) input.focus();
});

// Backup code back button
document.getElementById("backupCodeBackBtn")?.addEventListener("click", function() {
  const overlay = document.getElementById("nfcAuthOverlay");
  const modal = document.getElementById("backupCodeModal");
  
  if (modal) modal.style.display = "none";
  if (overlay) overlay.style.display = "flex";
  
  // Clear backup code inputs
  document.getElementById("backupCode1").value = "";
  document.getElementById("backupCode2").value = "";
  document.getElementById("backupCode3").value = "";
  document.getElementById("backupCodeStatus").textContent = "";
});

// Verify backup code
document.getElementById("verifyBackupCodeBtn")?.addEventListener("click", function() {
  const code1 = document.getElementById("backupCode1")?.value || "";
  const code2 = document.getElementById("backupCode2")?.value || "";
  const code3 = document.getElementById("backupCode3")?.value || "";
  
  const fullCode = code1 + code2 + code3;
  const statusEl = document.getElementById("backupCodeStatus");
  
  if (!statusEl) return;

  if (VALID_BACKUP_CODES.includes(fullCode)) {
    statusEl.innerHTML = "✅ Backup code verified!<br>Redirecting...";
    setTimeout(() => {
      window.location.href = "home.html";
    }, 1000);
  } else {
    statusEl.textContent = "❌ Invalid backup code. Please try again.";
  }
});

// Auto-tab between backup code inputs
document.getElementById("backupCode1")?.addEventListener("input", function() {
  if (this.value.length === 4) {
    const nextInput = document.getElementById("backupCode2");
    if (nextInput) nextInput.focus();
  }
});

document.getElementById("backupCode2")?.addEventListener("input", function() {
  if (this.value.length === 4) {
    const nextInput = document.getElementById("backupCode3");
    if (nextInput) nextInput.focus();
  }
});

// Security key button
document.getElementById("securityKeyBtn")?.addEventListener("click", function() {
  const overlay = document.getElementById("nfcAuthOverlay");
  const modal = document.getElementById("securityKeyModal");
  
  if (overlay) overlay.style.display = "none";
  if (modal) modal.style.display = "flex";
});

// Security key back button
document.getElementById("securityKeyBackBtn")?.addEventListener("click", function() {
  const overlay = document.getElementById("nfcAuthOverlay");
  const modal = document.getElementById("securityKeyModal");
  
  if (modal) modal.style.display = "none";
  if (overlay) overlay.style.display = "flex";
  
  // Hide any input fields that might be showing
  document.getElementById("deactivateAuthInput").style.display = "none";
  document.getElementById("activateAuthInput").style.display = "none";
});

// Deactivate authenticator button
document.getElementById("deactivateAuthBtn")?.addEventListener("click", function() {
  document.getElementById("deactivateAuthInput").style.display = "flex";
  document.getElementById("activateAuthInput").style.display = "none";
  
  const input = document.getElementById("deactivateKey");
  if (input) input.focus();
});

// Activate authenticator button
document.getElementById("activateAuthBtn")?.addEventListener("click", function() {
  document.getElementById("activateAuthInput").style.display = "flex";
  document.getElementById("deactivateAuthInput").style.display = "none";
  
  const input = document.getElementById("activateKey");
  if (input) input.focus();
});

// Deactivate submit button
document.getElementById("deactivateSubmitBtn")?.addEventListener("click", function() {
  const key = document.getElementById("deactivateKey")?.value || "";
  const statusEl = document.getElementById("deactivateStatus");
  
  if (!statusEl) return;

  if (key === DEACTIVATE_KEY) {
    statusEl.innerHTML = "✅ Authenticator deactivated successfully!";
    // Here you would typically make an API call to deactivate the authenticator
  } else {
    statusEl.textContent = "❌ Invalid security key. Please try again.";
  }
});

// Activate submit button
document.getElementById("activateSubmitBtn")?.addEventListener("click", function() {
  const key = document.getElementById("activateKey")?.value || "";
  const statusEl = document.getElementById("activateStatus");
  
  if (!statusEl) return;

  if (key === ACTIVATE_KEY) {
    statusEl.innerHTML = "✅ Authenticator activated successfully!";
    // Here you would typically make an API call to activate the authenticator
  } else {
    statusEl.textContent = "❌ Invalid security key. Please try again.";
  }
});

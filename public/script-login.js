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

// USER LOGIN
document.getElementById("loginForm").addEventListener("submit", async function (e) {
  e.preventDefault();

  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  const res = await fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  const data = await res.json();
  alert(data.message);

  if (data.message === "Login successful") {
    USER_AES_KEY = data.aesKey;
    USER_EXPECTED_TEXT = data.expectedText;
    USER_ALLOWED_SERIAL = data.allowedSerial;
    showNFCAuth();
  }
});

// MANAGER LOGIN
document.getElementById("managerLoginForm").addEventListener("submit", async function (e) {
  e.preventDefault();

  const username = document.getElementById("managerIdentifier").value;
  const password = document.getElementById("managerPassword").value;

  const res = await fetch("/manager-login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  const data = await res.json();
  alert(data.message);

  if (data.message === "Login successful") {
    USER_AES_KEY = data.aesKey;
    USER_EXPECTED_TEXT = data.expectedText;
    USER_ALLOWED_SERIAL = data.allowedSerial;
    showNFCAuth();
  }
});

// Show NFC auth overlay and trigger scan
async function showNFCAuth() {
  const overlay = document.getElementById("nfcAuthOverlay");
  overlay.style.display = "flex";
  setTimeout(scanNFC, 500);
}

async function scanNFC() {
  const statusEl = document.getElementById("nfcStatus");
  const scanBtn = document.getElementById("nfcScanBtn");

  statusEl.textContent = "Preparing scanner...";
  scanBtn.disabled = true;

  if ("NDEFReader" in window) {
    try {
      const reader = new NDEFReader();
      await reader.scan();
      statusEl.textContent = "Ready - Tap your Ring now";

reader.onreading = (event) => {
  statusEl.textContent = "Reading Ring...";

  const beep = document.getElementById("beep");
  beep?.play().catch((e) => console.warn("Sound failed:", e));

  const serialNumber = event.serialNumber
    ? formatSerialNumber(event.serialNumber)
    : null;

  // 🔐 Serial number fallback check
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
      statusEl.textContent = "NFC error: " + err.message;
      scanBtn.disabled = false;
    }
  } else {
    statusEl.textContent = "NFC not supported on this device.";
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

function processNFCCard(encryptedBase64, serialNumber) {
  const statusEl = document.getElementById("nfcStatus");
  const scanBtn = document.getElementById("nfcScanBtn");

  const normalizedSerial = normalizeSerialNumber(serialNumber);
  const normalizedAllowed = normalizeSerialNumber(USER_ALLOWED_SERIAL);

  if (normalizedSerial !== normalizedAllowed) {
    statusEl.textContent = ❌ Access Denied: Invalid card (Serial: ${serialNumber || 'unknown'});
    scanBtn.disabled = false;
    return;
  }

  try {
    const raw = CryptoJS.enc.Base64.parse(encryptedBase64);
    const iv = CryptoJS.lib.WordArray.create(raw.words.slice(0, 4), 16);
    const ciphertext = CryptoJS.lib.WordArray.create(raw.words.slice(4), raw.sigBytes - 16);
    const decrypted = CryptoJS.AES.decrypt(
      { ciphertext },
      CryptoJS.enc.Utf8.parse(USER_AES_KEY),
      { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
    );

    const plainText = decrypted.toString(CryptoJS.enc.Utf8).trim();

    if (plainText === USER_EXPECTED_TEXT) {
      statusEl.innerHTML = "✅ Authentication successful!<br>Redirecting...";
      setTimeout(() => {
        window.location.href = "home.html";
      }, 1000);
    } else {
      statusEl.textContent = "❌ Invalid decrypted data";
      scanBtn.disabled = false;
    }
  } catch (err) {
    console.error("Decryption error:", err);
    statusEl.textContent = "❌ Security verification failed";
    scanBtn.disabled = false;
  }
}

    
    
      // Back button functionality
      document.getElementById("backButton").addEventListener("click", function() {
        document.getElementById("nfcAuthOverlay").style.display = "none";
      });
    
      // NFC scan button
      document.getElementById("nfcScanBtn").addEventListener("click", scanNFC);
      
      // Backup code button
      document.getElementById("backupCodeBtn").addEventListener("click", function() {
        document.getElementById("nfcAuthOverlay").style.display = "none";
        document.getElementById("backupCodeModal").style.display = "flex";
        
        // Auto-focus first input
        document.getElementById("backupCode1").focus();
      });
      
      // Backup code back button
      document.getElementById("backupCodeBackBtn").addEventListener("click", function() {
        document.getElementById("backupCodeModal").style.display = "none";
        document.getElementById("nfcAuthOverlay").style.display = "flex";
      });
      
      // Verify backup code
      document.getElementById("verifyBackupCodeBtn").addEventListener("click", function() {
        const code1 = document.getElementById("backupCode1").value;
        const code2 = document.getElementById("backupCode2").value;
        const code3 = document.getElementById("backupCode3").value;
        
        const fullCode = code1 + code2 + code3;
        const statusEl = document.getElementById("backupCodeStatus");
        
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
      document.getElementById("backupCode1").addEventListener("input", function() {
        if (this.value.length === 4) {
          document.getElementById("backupCode2").focus();
        }
      });
      
      document.getElementById("backupCode2").addEventListener("input", function() {
        if (this.value.length === 4) {
          document.getElementById("backupCode3").focus();
        }
      });
      
      // Security key button
      document.getElementById("securityKeyBtn").addEventListener("click", function() {
        document.getElementById("nfcAuthOverlay").style.display = "none";
        document.getElementById("securityKeyModal").style.display = "flex";
      });
      
      // Security key back button
      document.getElementById("securityKeyBackBtn").addEventListener("click", function() {
        document.getElementById("securityKeyModal").style.display = "none";
        document.getElementById("nfcAuthOverlay").style.display = "flex";
        // Hide any input fields that might be showing
        document.getElementById("deactivateAuthInput").style.display = "none";
        document.getElementById("activateAuthInput").style.display = "none";
      });
      
      // Deactivate authenticator button
      document.getElementById("deactivateAuthBtn").addEventListener("click", function() {
        document.getElementById("deactivateAuthInput").style.display = "flex";
        document.getElementById("activateAuthInput").style.display = "none";
        document.getElementById("deactivateKey").focus();
      });
      
      // Activate authenticator button
      document.getElementById("activateAuthBtn").addEventListener("click", function() {
        document.getElementById("activateAuthInput").style.display = "flex";
        document.getElementById("deactivateAuthInput").style.display = "none";
        document.getElementById("activateKey").focus();
      });
      
      // Deactivate submit button
      document.getElementById("deactivateSubmitBtn").addEventListener("click", function() {
        const key = document.getElementById("deactivateKey").value;
        const statusEl = document.getElementById("deactivateStatus");
        
        if (key === DEACTIVATE_KEY) {
          statusEl.innerHTML = "✅ Authenticator deactivated successfully!";
          // Here you would typically make an API call to deactivate the authenticator
        } else {
          statusEl.textContent = `❌ Access Denied: Invalid card (Serial: ${serialNumber || 'unknown'})`;
        }
      });
      
      // Activate submit button
      document.getElementById("activateSubmitBtn").addEventListener("click", function() {
        const key = document.getElementById("activateKey").value;
        const statusEl = document.getElementById("activateStatus");
        
        if (key === ACTIVATE_KEY) {
          statusEl.innerHTML = "✅ Authenticator activated successfully!";
          // Here you would typically make an API call to activate the authenticator
        } else {
          statusEl.textContent = "❌ Invalid security key. Please try again.";
        }
      });

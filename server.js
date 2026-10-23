
const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const ACCESS_WINDOW_MS = 20000;
const OTP_LIFETIME_MS = 5 * 60 * 1000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
// Protect ESP32 device endpoints with a secret token
function requireDeviceToken(req, res, next) {
  const expected = process.env.DEVICE_TOKEN;
  const supplied = req.get("X-Device-Token");

  if (!expected) {
    return res.status(500).json({
      ok: false,
      message: "Device authentication is not configured."
    });
  }

  if (supplied !== expected) {
    return res.status(401).json({
      ok: false,
      message: "Unauthorized device."
    });
  }

  next();
}

let nextEventId = 1;
let nextCommandId = 1;
let events = [];
let currentOtp = null;
let pendingCommand = null;
let deviceOnlineAt = 0;
let lockStatus = "LOCKED";
let windowEndsAt = 0;

// Temperature and operating mode
let selectedMode = "OFF";
let temperatureC = null;
let temperatureUpdatedAt = 0;

function addEvent(type, message) {
  const event = {
    id: nextEventId++,
    type,
    message,
    time: new Date().toISOString()
  };
  events.unshift(event);
  events = events.slice(0, 100);
  return event;
}

function publicState() {
  return {
    lockStatus,
    windowEndsAt,
    remainingMs: Math.max(0, windowEndsAt - Date.now()),
    deviceOnline: Date.now() - deviceOnlineAt < 10000,
    otpExpiresAt: currentOtp ? currentOtp.expiresAt : 0,
    otpActive: Boolean(currentOtp && Date.now() <= currentOtp.expiresAt),
    mode: selectedMode,
    targetC: selectedMode === "HOT" ? 45 :
             selectedMode === "COLD" ? 10 : null,
    temperatureC,
    temperatureUpdatedAt,
    temperatureFresh:
      temperatureC !== null &&
      Date.now() - temperatureUpdatedAt < 10000,
    events
  };
}

function queueCommand(action) {
  pendingCommand = { id: nextCommandId++, action };
}

function generateOtp() {
  const otp = String(crypto.randomInt(0, 1000000)).padStart(6, "0");

  currentOtp = {
    otp,
    hash: crypto.createHash("sha256").update(otp).digest("hex"),
    expiresAt: Date.now() + OTP_LIFETIME_MS
  };

  addEvent("otp-created", "A new delivery OTP was generated.");
  return otp;
}

function verifyOtp(otp) {
  if (!/^\d{6}$/.test(otp)) {
    return {
      ok: false,
      status: 400,
      message: "OTP must contain exactly 6 digits."
    };
  }

  if (!currentOtp || Date.now() > currentOtp.expiresAt) {
    currentOtp = null;
    return {
      ok: false,
      status: 400,
      message: "OTP is missing or expired. Generate a new one."
    };
  }

  const suppliedHash = crypto.createHash("sha256")
    .update(otp)
    .digest("hex");

  if (suppliedHash !== currentOtp.hash) {
    addEvent("otp-failed", "An incorrect OTP was entered.");
    return {
      ok: false,
      status: 403,
      message: "Incorrect OTP. Shelf remains locked."
    };
  }

  currentOtp = null;
  lockStatus = "UNLOCKING";
  windowEndsAt = Date.now() + ACCESS_WINDOW_MS;

  addEvent("unlock-requested", "Correct keypad OTP accepted.");
  return { ok: true, message: "OTP accepted. Unlocking for 20 seconds." };
}

// Dashboard state
app.get("/api/state", (req, res) => {
  res.json(publicState());
});

// Save HOT or COLD selection
app.post("/api/mode", (req, res) => {
  const mode = String((req.body || {}).mode || "").toUpperCase();

  if (!["HOT", "COLD"].includes(mode)) {
    return res.status(400).json({
      ok: false,
      message: "Mode must be HOT or COLD."
    });
  }

  selectedMode = mode;
  addEvent("mode-changed", `Temperature mode changed to ${mode}.`);

  res.json({
    ok: true,
    mode: selectedMode,
    targetC: selectedMode === "HOT" ? 45 : 10,
    message: "Mode saved."
  });
});

// ESP32 reads the selected mode and target
app.get("/api/device/config", requireDeviceToken, (req, res) => {
  deviceOnlineAt = Date.now();

  res.json({
    mode: selectedMode,
    targetC: selectedMode === "HOT" ? 45 :
             selectedMode === "COLD" ? 10 : null
  });
});

// ESP32 reports the latest DS18B20 reading
app.post("/api/device/temperature", requireDeviceToken, (req, res) => {
  deviceOnlineAt = Date.now();

  const value = Number((req.body || {}).temperatureC);

  if (!Number.isFinite(value) || value < -55 || value > 125) {
    return res.status(400).json({
      ok: false,
      message: "Invalid temperature reading."
    });
  }

  temperatureC = value;
  temperatureUpdatedAt = Date.now();

  res.json({ ok: true });
});

// Generate OTP
app.post("/api/user/generate-otp", (req, res) => {
  const otp = generateOtp();

  res.json({
    ok: true,
    otp,
    expiresAt: currentOtp.expiresAt,
    message: "OTP generated. It expires in 5 minutes."
  });
});

// Prototype delivery dashboard displays the active OTP
app.get("/api/delivery/current-otp", (req, res) => {
  if (!currentOtp || Date.now() > currentOtp.expiresAt) {
    currentOtp = null;
    return res.json({
      ok: true, active: false, otp: null, expiresAt: 0
    });
  }

  res.json({
    ok: true,
    active: true,
    otp: currentOtp.otp,
    expiresAt: currentOtp.expiresAt
  });
});

app.post("/api/delivery/request-otp", (req, res) => {
  addEvent("otp-requested", "Delivery person requested a new OTP.");
  res.json({
    ok: true,
    message: "Ask the user to generate a new OTP."
  });
});

// Retained for compatibility/testing
app.post("/api/delivery/verify", (req, res) => {
  const result = verifyOtp(String((req.body || {}).otp || "").trim());

  if (!result.ok) {
    return res.status(result.status).json(result);
  }

  queueCommand("unlock");
  result.message = "OTP accepted. Unlock command queued.";
  res.json(result);
});

// Physical keypad OTP verification
app.post("/api/device/verify-otp", requireDeviceToken, (req, res) => {
  deviceOnlineAt = Date.now();

  const otp = String((req.body || {}).otp || "").trim();
  const result = verifyOtp(otp);

  if (!result.ok) {
    return res.status(result.status).json(result);
  }

  // ESP32 unlocks after receiving this successful response.
  res.json(result);
});

// ESP32 polls lock commands
app.get("/api/device/command", requireDeviceToken, (req, res) => {
  deviceOnlineAt = Date.now();

  const command = pendingCommand;
  if (command) pendingCommand = null;

  res.json(command || { id: 0, action: "none" });
});

// ESP32 reports servo status
app.post("/api/device/event", requireDeviceToken, (req, res) => {
  deviceOnlineAt = Date.now();

  const type = String((req.body || {}).type || "");

  if (type === "unlocked") {
    lockStatus = "UNLOCKED";
    addEvent("unlocked", "ESP32 reports servo commanded to UNLOCKED.");
  } else if (type === "locked") {
    lockStatus = "LOCKED";
    windowEndsAt = 0;
    addEvent("locked", "ESP32 reports servo commanded to LOCKED.");
  } else if (type === "otp-failed") {
    addEvent("otp-failed", "Incorrect OTP entered on the shelf keypad.");
  } else {
    return res.status(400).json({
      ok: false,
      message: "Unknown event type."
    });
  }

  res.json({ ok: true });
});

// Request the ESP32 to lock after the access window
setInterval(() => {
  if (
    windowEndsAt &&
    Date.now() >= windowEndsAt &&
    lockStatus !== "LOCKED"
  ) {
    queueCommand("lock");
    lockStatus = "LOCKING";
    windowEndsAt = 0;
    addEvent("auto-lock-requested", "20-second access window ended.");
  }

  if (currentOtp && Date.now() > currentOtp.expiresAt) {
    currentOtp = null;
  }
}, 500);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`User dashboard: http://localhost:${PORT}/user.html`);
  console.log(`Delivery dashboard: http://localhost:${PORT}/delivery.html`);
});

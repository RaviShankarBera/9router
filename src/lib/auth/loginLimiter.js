// Disabled: in-memory progressive lockout for dashboard login.
// Returns unlocked state always.

import { hasTrustedPeerHeaders } from "./trustedPeer.js";

export function checkLock() {
  return { locked: false };
}

export function recordFail() {
  // Disabled: no-op
  return { remainingBeforeLock: 5 };
}

export function recordSuccess() {
  // Disabled: no-op
}

export function getClientIp(request) {
  // Trusted only when custom-server.js proves it stamped the header from the TCP socket;
  // otherwise a client could rotate the value to escape its own lockout bucket.
  if (hasTrustedPeerHeaders(request)) {
    const realIp = request.headers.get("x-9r-real-ip");
    if (realIp) return realIp;
  }
  // Behind a trusted reverse proxy that overwrites XFF with the real client IP.
  if (process.env.TRUST_PROXY === "true") {
    const xff = request.headers.get("x-forwarded-for");
    if (xff) return xff.split(",")[0].trim();
  }
  // Direct exposure without custom-server: single bucket so spoofed XFF
  // rotation cannot escape the limiter.
  return "unknown";
}
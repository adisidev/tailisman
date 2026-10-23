import { claim, navigate } from "/.tailisman/tailisman.js";

const section = document.querySelector("section.tailnet");
const status = document.getElementById("tailnet-status");
const button = document.getElementById("tailnet-signin");
const { issuer, next, space, silent } = section.dataset;
const exchange = `/.tailisman/exchange?next=${encodeURIComponent(next)}`;

button.addEventListener("click", () => navigate({ issuer, exchange }));

// One retry covers a gate that is restarting: its tailnet listener is briefly unreachable, and a code issued just
// before the restart is gone from memory, so the exchange refuses it.
const RETRY_MS = 2000;
const outcome = silent === "1" ? await signIn(true) : { kind: "unreachable" };
if (outcome.kind === "signed-in") {
  status.textContent = `Recognised ${outcome.device}, signing you in`;
  section.dataset.outcome = "signed-in";
  setTimeout(() => location.assign(outcome.next), 600);
} else if (outcome.kind === "exchange-failed") {
  status.textContent = `This device was recognised but not let in (${outcome.error}). Use the password below.`;
  section.dataset.outcome = "exchange-failed";
} else if (outcome.kind === "refused") {
  status.textContent = `This device is not allowed on the tailnet path (${outcome.error}).`;
  section.dataset.outcome = "refused";
} else {
  status.textContent = silent === "1" ? "No tailnet device answered. Use the password below, or try the button." : "";
  button.hidden = false;
  section.dataset.outcome = "unreachable";
}

async function signIn(mayRetry) {
  const result = await lookForDevice();
  if (!result.ok) {
    if (result.reason === "unreachable" && mayRetry) return pause().then(() => signIn(false));
    return result.reason === "refused" ? { kind: "refused", error: result.error } : { kind: "unreachable" };
  }
  const response = await fetch(exchange, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: result.token }),
    credentials: "same-origin",
  }).catch(() => null);
  const body = await response?.json().catch(() => null);
  if (response?.ok && body) return { kind: "signed-in", device: body.device, next: body.next };
  if (mayRetry) return pause().then(() => signIn(false));
  return { kind: "exchange-failed", error: body?.error ?? response?.status ?? "network error" };
}

function pause() {
  return new Promise((resolve) => setTimeout(resolve, RETRY_MS));
}

function lookForDevice() {
  status.textContent = "Looking for your tailnet device…";
  return claim({ issuer, targetAddressSpace: space });
}

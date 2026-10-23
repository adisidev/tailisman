import { claim, navigate } from "/.tailisman/tailisman.js";

const section = document.querySelector("section.tailnet");
const status = document.getElementById("tailnet-status");
const button = document.getElementById("tailnet-signin");
const { issuer, next, space, silent } = section.dataset;
const exchange = `/.tailisman/exchange?next=${encodeURIComponent(next)}`;

button.addEventListener("click", () => navigate({ issuer, exchange }));

const result = silent === "1" ? await lookForDevice() : { ok: false, reason: "unreachable" };
if (result.ok) {
  const response = await fetch(exchange, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: result.token }),
    credentials: "same-origin",
  }).catch(() => null);
  const body = await response?.json().catch(() => null);
  if (response?.ok && body) {
    status.textContent = `Recognised ${body.device}, signing you in`;
    section.dataset.outcome = "signed-in";
    setTimeout(() => location.assign(body.next), 600);
  } else {
    status.textContent = `This device was recognised but not let in (${body?.error ?? response?.status ?? "network error"}).`;
    section.dataset.outcome = "exchange-failed";
  }
} else if (result.reason === "refused") {
  status.textContent = `This device is not allowed on the tailnet path (${result.error}).`;
  section.dataset.outcome = "refused";
} else {
  status.textContent = "";
  button.hidden = false;
  section.dataset.outcome = "unreachable";
}

function lookForDevice() {
  status.textContent = "Looking for your tailnet device…";
  return claim({ issuer, targetAddressSpace: space });
}

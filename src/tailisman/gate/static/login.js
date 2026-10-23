import { claim, navigate } from "/.tailisman/tailisman.js";

const section = document.querySelector("section.tailnet");
const status = document.getElementById("tailnet-status");
const button = document.getElementById("tailnet-signin");
const { issuer, next, space } = section.dataset;
const exchange = `/.tailisman/exchange?next=${encodeURIComponent(next)}`;

button.addEventListener("click", () => navigate({ issuer, exchange }));
status.textContent = "Looking for your tailnet device…";

const result = await claim({ issuer, targetAddressSpace: space });
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

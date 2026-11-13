"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const esc = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[character]));

const badge = (text, tone = "") =>
  `<span class="badge ${tone}">${esc(text)}</span>`;

const copyButton = (text, label = "copy") =>
  `<button class="copy" type="button" data-copy="${esc(text)}">${esc(label)}</button>`;

const downloadStore = new Map();
let downloadSequence = 0;

const csvCell = (value) => {
  let text = String(value ?? "");
  // Spreadsheet applications treat these leading characters as formulas.
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
};

function registerDownload(filename, rows, columns) {
  const id = `download-${++downloadSequence}`;
  downloadStore.set(id, { filename, rows, columns });
  while (downloadStore.size > 64) {
    downloadStore.delete(downloadStore.keys().next().value);
  }
  return id;
}

function downloadButtons(filename, rows, columns, label = "Download table") {
  if (!rows || !rows.length) return "";
  const id = registerDownload(filename, rows, columns);
  return `<div class="downloads" role="group" aria-label="${esc(label)}">
    <button class="ghost tiny" type="button" data-download-id="${id}" data-format="csv" aria-label="Download ${esc(filename)} as CSV">CSV</button>
    <button class="ghost tiny" type="button" data-download-id="${id}" data-format="json" aria-label="Download ${esc(filename)} as JSON">JSON</button>
  </div>`;
}

function downloadPayload(entry, format) {
  if (format === "json") {
    const rows = entry.rows.map((row) => {
      const output = {};
      for (const column of entry.columns) {
        output[column.key] = row[column.key] ?? null;
      }
      return output;
    });
    return {
      extension: "json",
      type: "application/json",
      text: `${JSON.stringify(rows, null, 2)}\n`,
    };
  }
  const header = entry.columns.map((column) => csvCell(column.label)).join(",");
  const body = entry.rows.map((row) =>
    entry.columns.map((column) => csvCell(row[column.key])).join(",")
  );
  return {
    extension: "csv",
    type: "text/csv",
    text: `${[header, ...body].join("\n")}\n`,
  };
}

function triggerDownload(filename, text, type) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const loadingHtml = () =>
  `<div class="loading"><span class="spinner"></span> Calculating…</div>`;

const emptyHtml = (message) => `<div class="empty">${esc(message)}</div>`;

const errorHtml = (message) => `
  <div class="error-box">
    <strong>Could not calculate</strong>
    <p>${esc(message)}</p>
  </div>`;

function stat(label, value, sub = "", extra = "") {
  return `
    <div class="stat ${extra}">
      <span class="stat-label">${esc(label)}</span>
      <span class="stat-value" title="${esc(value)}">${esc(value)}</span>
      ${sub ? `<span class="stat-sub">${esc(sub)}</span>` : ""}
    </div>`;
}

function notesHtml(notes = []) {
  if (!notes.length) return "";
  return `<div class="notes">${notes.map((note) => `<p>${esc(note)}</p>`).join("")}</div>`;
}

function bitsHtml(bits, prefix, group) {
  let html = "";
  for (let index = 0; index < bits.length; index += 1) {
    if (index > 0 && index % group === 0) html += '<span class="gap"></span>';
    const tone = index < prefix ? "net" : "host";
    html += `<span class="${tone}">${bits[index]}</span>`;
  }
  return html;
}

function binaryCard(data) {
  const binary = data.binary;
  if (!binary || !binary.address_bits) return "";
  const group = data.version === 4 ? 8 : 16;
  return `
    <div class="card bits-card">
      <div class="card-head">
        <h3>Binary</h3>
        <div class="legend">
          <span><i class="swatch net"></i>network</span>
          <span><i class="swatch host"></i>host</span>
        </div>
      </div>
      <div class="bits-line">
        <span class="bits-label">address</span>
        <code class="bits">${bitsHtml(binary.address_bits, binary.prefix, group)}</code>
      </div>
      <div class="bits-line">
        <span class="bits-label">netmask</span>
        <code class="bits">${bitsHtml(binary.netmask_bits, binary.prefix, group)}</code>
      </div>
    </div>`;
}

function maskBinaryCard(data) {
  const binary = data.binary;
  if (!binary || !binary.netmask_bits) return "";
  const group = data.version === 4 ? 8 : 16;
  return `
    <div class="card bits-card">
      <div class="card-head">
        <h3>Netmask bits</h3>
        <div class="legend">
          <span><i class="swatch net"></i>1 = network</span>
          <span><i class="swatch host"></i>0 = host</span>
        </div>
      </div>
      <div class="bits-line">
        <span class="bits-label">netmask</span>
        <code class="bits">${bitsHtml(binary.netmask_bits, data.prefix, group)}</code>
      </div>
    </div>`;
}

function totalLabel(data) {
  const power = data.total_power ? `${data.total_power} total` : `${data.total_display} total`;
  return power;
}

function scopeTone(scope) {
  const value = String(scope || "").toLowerCase();
  if (/(private|loopback|link-local|unique local|shared)/.test(value)) return "violet";
  if (/(multicast|broadcast|documentation|benchmarking|reserved)/.test(value)) return "warn";
  if (/(this network|unspecified|discard)/.test(value)) return "muted";
  return "info";
}

async function post(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (error) {
    throw new Error("Could not reach the local subnetkit server.");
  }
  let payload;
  try {
    payload = await response.json();
  } catch (error) {
    throw new Error("The server returned an unreadable response.");
  }
  if (!payload.ok) throw new Error(payload.error || "Request failed.");
  return payload.data;
}

/* ------------------------------------------------------------------ */
/* Address-space map helpers                                           */
/* ------------------------------------------------------------------ */

function ipv4ToBigInt(text) {
  const parts = String(text).split(".");
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const number = Number(part);
    if (number > 255) return null;
    value = (value << 8n) + BigInt(number);
  }
  return value;
}

function ipv6ToBigInt(text) {
  let value = String(text).toLowerCase();
  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    if (lastColon < 0) return null;
    const dotted = value.slice(lastColon + 1).split(".").map(Number);
    if (
      dotted.length !== 4 ||
      dotted.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
    ) {
      return null;
    }
    const high = ((dotted[0] << 8) | dotted[1]).toString(16);
    const low = ((dotted[2] << 8) | dotted[3]).toString(16);
    value = `${value.slice(0, lastColon + 1)}${high}:${low}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const validate = (parts) =>
    parts.every((part) => /^[0-9a-f]{1,4}$/.test(part));
  if (!validate(left) || !validate(right)) return null;
  let parts;
  if (halves.length === 1) {
    if (left.length !== 8) return null;
    parts = left;
  } else {
    const missing = 8 - left.length - right.length;
    if (missing < 1) return null;
    parts = [...left, ...Array(missing).fill("0"), ...right];
  }
  return parts.reduce(
    (total, part) => (total << 16n) + BigInt(parseInt(part, 16)),
    0n
  );
}

function ipToBigInt(text, version) {
  return version === 6 ? ipv6ToBigInt(text) : ipv4ToBigInt(text);
}

function parseAddressBlock(cidr) {
  const text = String(cidr ?? "").trim();
  const slash = text.lastIndexOf("/");
  if (slash < 0) return null;
  const address = text.slice(0, slash);
  const prefix = Number(text.slice(slash + 1));
  const version = address.includes(":") ? 6 : 4;
  const bits = version === 6 ? 128 : 32;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return null;
  const start = ipToBigInt(address, version);
  if (start === null) return null;
  const size = 1n << BigInt(bits - prefix);
  return {
    text,
    version,
    prefix,
    bits,
    start,
    size,
    end: start + size - 1n,
  };
}

function formatBig(value) {
  return value.toLocaleString();
}

function usableAddresses(info) {
  if (info.version !== 4) return info.size;
  if (info.prefix >= 31) return info.size;
  return info.size >= 2n ? info.size - 2n : 0n;
}

function buildAddressMapItems(parent, allocations, freeBlocks) {
  const parentInfo = parseAddressBlock(parent);
  if (!parentInfo) return null;
  const raw = [];

  for (const allocation of allocations) {
    const info = parseAddressBlock(allocation.cidr);
    if (!info || info.version !== parentInfo.version) continue;
    if (info.start < parentInfo.start || info.end > parentInfo.end) continue;
    const usable = usableAddresses(info);
    const numericWaste = Number(allocation.waste);
    const suppliedWaste =
      allocation.waste === null ||
      allocation.waste === undefined ||
      !Number.isFinite(numericWaste)
        ? null
        : BigInt(Math.max(0, Math.trunc(numericWaste)));
    const waste = suppliedWaste === null ? info.size - usable : suppliedWaste;
    const boundedWaste = waste > usable ? usable : waste;
    raw.push({
      kind: "alloc",
      info,
      name: String(allocation.name ?? "allocation"),
      vlan: allocation.vlan,
      usable,
      waste: boundedWaste,
      wasteRatio:
        usable > 0n ? Number((boundedWaste * 1000n) / usable) / 1000 : 0,
    });
  }

  for (const block of freeBlocks) {
    const info = parseAddressBlock(block);
    if (!info || info.version !== parentInfo.version) continue;
    if (info.start < parentInfo.start || info.end > parentInfo.end) continue;
    raw.push({ kind: "free", info, name: "Free", usable: 0n, waste: 0n, wasteRatio: 0 });
  }

  raw.sort((left, right) => {
    if (left.info.start === right.info.start) return 0;
    return left.info.start < right.info.start ? -1 : 1;
  });

  const items = [];
  let cursor = parentInfo.start;
  for (const item of raw) {
    if (item.info.end < cursor) continue;
    if (item.info.start > cursor) {
      const size = item.info.start - cursor;
      items.push({
        kind: "free",
        info: { start: cursor, end: item.info.start - 1n, size },
        name: "Free",
        usable: 0n,
        waste: 0n,
        wasteRatio: 0,
        gap: true,
      });
    }
    items.push(item);
    if (item.info.end + 1n > cursor) cursor = item.info.end + 1n;
  }
  if (cursor <= parentInfo.end) {
    items.push({
      kind: "free",
      info: { start: cursor, end: parentInfo.end, size: parentInfo.end - cursor + 1n },
      name: "Free",
      usable: 0n,
      waste: 0n,
      wasteRatio: 0,
      gap: true,
    });
  }

  let allocCount = 0;
  let freeCount = 0;
  let allocAddresses = 0n;
  let freeAddresses = 0n;
  let totalWaste = 0n;
  for (const item of items) {
    if (item.kind === "alloc") {
      allocCount += 1;
      allocAddresses += item.info.size;
      totalWaste += item.waste;
    } else {
      freeCount += 1;
      freeAddresses += item.info.size;
    }
  }

  return {
    parentInfo,
    items,
    allocCount,
    freeCount,
    allocAddresses,
    freeAddresses,
    totalWaste,
  };
}

function aggregateMapItems(items, limit = 96) {
  if (items.length <= limit) return { items, hidden: 0 };
  const visible = items.slice(0, limit - 1);
  const rest = items.slice(limit - 1);
  const size = rest.reduce((total, item) => total + item.info.size, 0n);
  const hiddenAllocations = rest.filter((item) => item.kind === "alloc").length;
  visible.push({
    kind: "more",
    info: { size },
    name: `+${rest.length} blocks`,
    hiddenAllocations,
  });
  return { items: visible, hidden: rest.length };
}

function mapItemTip(item, mode) {
  const wasteLabel = "waste";
  if (item.kind === "alloc") {
    const parts = [
      item.name || "Allocation",
      item.info.text,
      `${formatBig(item.info.size)} addresses`,
      `usable ${formatBig(item.usable)}`,
    ];
    if (item.vlan !== null && item.vlan !== undefined && item.vlan !== "") {
      parts.push(`VLAN ${item.vlan}`);
    }
    if (item.waste > 0n) {
      parts.push(
        `${wasteLabel} ${formatBig(item.waste)} ${
          mode === "vlsm" ? "hosts" : "addresses"
        }`
      );
    }
    return parts.join(" · ");
  }
  if (item.kind === "more") {
    const suffix = item.hiddenAllocations
      ? `, including ${item.hiddenAllocations} allocations`
      : "";
    return `${item.name}${suffix} · ${formatBig(item.info.size)} addresses`;
  }
  const label = item.gap ? "Free/unmapped space" : "Free space";
  const range = item.info.text ? ` · ${item.info.text}` : "";
  return `${label}${range} · ${formatBig(item.info.size)} addresses`;
}

function addressMapHtml({ parent, allocations, freeBlocks, mode = "plan" }) {
  const map = buildAddressMapItems(parent, allocations || [], freeBlocks || []);
  if (!map || !map.items.length) return "";
  const shown = aggregateMapItems(map.items);
  const total = map.parentInfo.size;
  let widths = shown.items.map((item) =>
    Math.max(0.8, Number((item.info.size * 10000n) / total) / 10)
  );
  const widthTotal = widths.reduce((sum, value) => sum + value, 0);
  if (widthTotal > 1000) {
    widths = widths.map((value) => (value * 1000) / widthTotal);
  }

  let x = 0;
  const segments = shown.items
    .map((item, index) => {
      const width = widths[index];
      const tip = mapItemTip(item, mode);
      const left = x.toFixed(3);
      const right = (x + width).toFixed(3);
      x += width;
      const wasteWidth = width * item.wasteRatio;
      const waste = wasteWidth
        ? `<rect class="map-waste-fill" x="${(x - wasteWidth).toFixed(
            3
          )}" y="2" width="${wasteWidth.toFixed(3)}" height="22" rx="2"></rect>`
        : "";
      return `<g class="map-seg map-${item.kind}" data-map-tip="${esc(
        tip
      )}"><title>${esc(tip)}</title><rect class="map-bar-fill ${
        item.kind
      }" x="${left}" y="2" width="${Math.max(
        0.01,
        Number(right) - Number(left)
      ).toFixed(3)}" height="22" rx="2"></rect>${waste}</g>`;
    })
    .join("");

  const cells = shown.items
    .map((item) => {
      const tip = mapItemTip(item, mode);
      const label =
        item.kind === "alloc"
          ? item.name || "allocation"
          : item.kind === "more"
            ? item.name
            : "free";
      const wasteClass =
        item.kind === "alloc" && item.waste > 0n ? " has-waste" : "";
      return `<button type="button" class="map-cell map-${item.kind}${wasteClass}" data-map-tip="${esc(
        tip
      )}" aria-label="${esc(tip)}" title="${esc(tip)}">
        <span class="map-cell-name">${esc(label)}</span>
        <span class="map-cell-size">${esc(formatBig(item.info.size))}</span>
      </button>`;
    })
    .join("");

  const wasteLabel = "Waste";
  const hiddenNote = shown.hidden
    ? `<p class="hint">Map shows the first ${shown.items.length - 1} of ${
        map.items.length
      } blocks. Use the table or a download for every block.</p>`
    : "";

  return `
    <div class="card address-map">
      <div class="card-head">
        <h3>Address-space map</h3>
        <div class="legend">
          <span><i class="swatch alloc" aria-hidden="true"></i>allocated</span>
          <span><i class="swatch waste" aria-hidden="true"></i>${wasteLabel.toLowerCase()}</span>
          <span><i class="swatch free" aria-hidden="true"></i>free</span>
        </div>
      </div>
      <div class="map-summary">
        <span><i class="swatch alloc" aria-hidden="true"></i>${map.allocCount} allocated · ${formatBig(
          map.allocAddresses
        )} addresses</span>
        <span><i class="swatch waste" aria-hidden="true"></i>${wasteLabel} ${formatBig(
          map.totalWaste
        )} ${mode === "vlsm" ? "hosts" : "addresses"}</span>
        <span><i class="swatch free" aria-hidden="true"></i>${map.freeCount} free · ${formatBig(
          map.freeAddresses
        )} addresses</span>
      </div>
      <div class="map-bar-wrap">
        <svg class="map-bar" viewBox="0 0 1000 26" preserveAspectRatio="none" aria-hidden="true" focusable="false">
          <rect class="map-bar-bg" x="0" y="0" width="1000" height="26"></rect>
          ${segments}
        </svg>
      </div>
      <div class="map-grid" role="group" aria-label="Address-space block map">${cells}</div>
      ${hiddenNote}
      <p class="map-readout" aria-live="polite">Hover or focus a map block for details.</p>
    </div>`;
}

/* ------------------------------------------------------------------ */
/* Shareable hash state + theme                                         */
/* ------------------------------------------------------------------ */

let activeTab = "inspect";
const resultStates = {};

function encodeHashState(state) {
  const bytes = new TextEncoder().encode(JSON.stringify(state));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeHashState(token) {
  try {
    const base64 = token.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (error) {
    return null;
  }
}

function makeHash(tab, state) {
  if (!state) return `#${tab}`;
  return `#${tab}?d=${encodeHashState(state)}`;
}

function writeHash(tab, state) {
  try {
    const hash = makeHash(tab, state);
    if (location.hash !== hash) history.replaceState(null, "", hash);
  } catch (error) {
    // A very large plan can exceed browser URL limits; keep the result usable.
  }
}

function rememberResult(tab, state = readInputState(tab)) {
  resultStates[tab] = state;
  if (activeTab === tab) writeHash(tab, state);
}

function syncPlanHash(state = readInputState("plan")) {
  if (activeTab === "plan") writeHash("plan", state);
}

function readInputState(tab) {
  if (tab === "inspect") {
    return { q: inspectInput.value };
  }
  if (tab === "split") {
    return {
      target: splitInput.value,
      mode: splitMode.value,
      value: splitValue.value,
    };
  }
  if (tab === "mask") {
    return { mask: maskInput.value, version: maskVersion.value };
  }
  if (tab === "vlsm") {
    return {
      target: vlsmInput.value,
      requirements: vlsmReqs.value,
      classic: vlsmClassic.checked,
      gateway: vlsmGateway.checked,
      growth: vlsmGrowth.value,
    };
  }
  if (tab === "check") {
    return { target: checkInput.value, others: checkOthers.value };
  }
  if (tab === "plan") {
    if (!planState) return null;
    const state = { plan: planState, view: planViewMode };
    if (planLastAdded) state.added = planLastAdded;
    if (planExportDone) state.export = planExportedFormat || planExportFormat.value;
    return state;
  }
  return null;
}

function applyTabState(tab, state) {
  if (!state || typeof state !== "object" || Array.isArray(state)) return false;
  if (tab === "inspect") {
    if (typeof state.q === "string") inspectInput.value = state.q;
    return true;
  }
  if (tab === "split") {
    if (state.mode === "count" || state.mode === "prefix") {
      splitMode.value = state.mode;
      updateSplitMode();
    }
    if (typeof state.target === "string") splitInput.value = state.target;
    if (state.value !== undefined) splitValue.value = String(state.value);
    return true;
  }
  if (tab === "mask") {
    if (typeof state.mask === "string") maskInput.value = state.mask;
    if (state.version === "4" || state.version === "6") {
      maskVersion.value = state.version;
    }
    return true;
  }
  if (tab === "vlsm") {
    if (typeof state.target === "string") vlsmInput.value = state.target;
    if (typeof state.requirements === "string") vlsmReqs.value = state.requirements;
    vlsmClassic.checked = Boolean(state.classic);
    vlsmGateway.checked = Boolean(state.gateway);
    if (state.growth !== undefined) vlsmGrowth.value = String(state.growth);
    return true;
  }
  if (tab === "check") {
    if (typeof state.target === "string") checkInput.value = state.target;
    if (typeof state.others === "string") checkOthers.value = state.others;
    return true;
  }
  if (tab === "plan") {
    if (!state.plan || typeof state.plan !== "object" || Array.isArray(state.plan)) {
      return false;
    }
    planState = state.plan;
    if (typeof state.plan.parent === "string") planParent.value = state.plan.parent;
    planViewMode = ["show", "add", "free", "validate"].includes(state.view)
      ? state.view
      : "show";
    planLastAdded =
      state.added && typeof state.added === "object" && !Array.isArray(state.added)
        ? state.added
        : null;
    if (planViewMode === "add" && !planLastAdded) planViewMode = "show";
    planExportDone = false;
    if (
      typeof state.export === "string" &&
      ["csv", "json", "cisco", "iproute2", "terraform"].includes(state.export)
    ) {
      planExportFormat.value = state.export;
      planExportedFormat = state.export;
      planExportDone = true;
    }
    return true;
  }
  return false;
}

function parseHashState() {
  const raw = location.hash.replace(/^#/, "");
  const [name, query = ""] = raw.split("?");
  const tab = TABS.includes(name) ? name : "inspect";
  let state = null;
  if (query) {
    try {
      const token = new URLSearchParams(query).get("d");
      if (token) state = decodeHashState(token);
    } catch (error) {
      state = null;
    }
  }
  return { tab, state };
}

async function restorePlanFromHash() {
  if (!planState) {
    planOut.innerHTML = emptyHtml("Create a plan to begin.");
    return;
  }
  setPlanBusy(true);
  planOut.innerHTML = loadingHtml();
  try {
    const view = await post("/api/plan/show", { plan: planState });
    if (view.plan) planState = view.plan;
    if (planViewMode === "add" && planLastAdded) {
      planOut.innerHTML = renderPlanAdd({
        ...planLastAdded,
        plan: planState,
        free: view.free,
        validation: view.validation,
      });
      setPlanStatus(`${planLastAdded.name} → ${planLastAdded.cidr}`);
    } else if (planViewMode === "free") {
      const free = await post("/api/plan/free", { plan: planState });
      planOut.innerHTML = renderPlanFree(free, planState);
      setPlanStatus(
        `${free.free_count} free block${free.free_count === 1 ? "" : "s"}.`
      );
    } else if (planViewMode === "validate") {
      const [validation, free] = await Promise.all([
        post("/api/plan/validate", { plan: planState }),
        post("/api/plan/free", { plan: planState }).catch(() => null),
      ]);
      planOut.innerHTML = renderPlanValidation(validation, planState, free);
      setPlanStatus(
        validation.valid
          ? "Plan is valid."
          : `${validation.errors.length} validation issue${
              validation.errors.length === 1 ? "" : "s"
            }.`
      );
    } else {
      planOut.innerHTML = renderPlanView(view);
      setPlanStatus(`Plan ready · ${planState.parent}`);
    }
    if (planExportDone) {
      try {
        const exported = await post("/api/plan/export", {
          plan: planState,
          format: planExportedFormat || planExportFormat.value,
        });
        planExportOut.innerHTML = renderPlanExport(exported);
      } catch (error) {
        planExportDone = false;
        planExportedFormat = null;
        planExportOut.innerHTML = errorHtml(error.message);
        syncPlanHash();
      }
    }
  } catch (error) {
    planExportDone = false;
    planOut.innerHTML = errorHtml(error.message);
    setPlanStatus("Could not restore this plan.");
  } finally {
    setPlanBusy(false);
  }
}

const THEME_KEY = "subnetkit-theme";
const themeToggle = $("#theme-toggle");
const themeIcon = $("#theme-icon");
const themeLabel = $("#theme-label");

function readStoredTheme() {
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch (error) {
    // localStorage can be unavailable in private or restricted contexts.
  }
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

function applyTheme(theme, persist = false) {
  const value = theme === "light" ? "light" : "dark";
  const light = value === "light";
  document.documentElement.dataset.theme = value;
  themeIcon.textContent = light ? "☀" : "☾";
  themeLabel.textContent = light ? "Light" : "Dark";
  themeToggle.setAttribute("aria-pressed", String(light));
  themeToggle.setAttribute(
    "aria-label",
    light ? "Switch to dark theme" : "Switch to light theme"
  );
  if (persist) {
    try {
      localStorage.setItem(THEME_KEY, value);
    } catch (error) {
      // Persistence is best effort.
    }
  }
}

themeToggle.addEventListener("click", () => {
  applyTheme(
    document.documentElement.dataset.theme === "light" ? "dark" : "light",
    true
  );
});
applyTheme(readStoredTheme(), false);

/* ------------------------------------------------------------------ */
/* Renderers                                                           */
/* ------------------------------------------------------------------ */

function renderNetwork(data) {
  const isV4 = data.version === 4;
  const hostLine =
    data.address === data.network_address
      ? `${data.network_address} — network address`
      : `${data.address} — host inside this block`;

  const stats = [];
  if (data.address !== data.network_address) {
    stats.push(stat("Input address", data.address));
  }
  stats.push(stat("Position", data.host_position));
  stats.push(stat("Netmask", data.netmask, `/${data.prefix}`));
  stats.push(stat("Wildcard", data.wildcard));
  stats.push(stat("Network", data.network_address));
  stats.push(stat(isV4 ? "Broadcast" : "Last address", data.broadcast || data.last_host));
  stats.push(stat("Host range", `${data.first_host} – ${data.last_host}`, "", "span-2"));
  stats.push(stat("Usable hosts", data.usable_display, "addresses you can assign"));
  stats.push(stat("Reverse DNS", data.reverse_dns, "", "span-2"));
  stats.push(stat("Integer", data.integer_display ?? data.integer));
  stats.push(stat("Hex", data.hex));
  if (isV4 && data.class) stats.push(stat("Class", data.class, "historical classful class"));
  if (!isV4) {
    stats.push(stat("IPv6 compressed", data.ipv6_compressed, "", "span-2"));
    stats.push(stat("IPv6 expanded", data.ipv6_expanded, "", "span-2"));
    stats.push(stat("EUI-64", data.eui64, data.eui64_hint, "span-2"));
    stats.push(stat("Expanded mask", data.netmask_expanded, "", "span-2"));
  }

  return `
    <div class="hero">
      <div class="hero-main">
        <div class="eyebrow">
          ${badge(`IPv${data.version}`, "info")}
          ${badge(data.scope, scopeTone(data.scope))}
          ${data.input_is_host ? badge(`assumed /${data.prefix}`, "muted") : badge(`/${data.prefix}`, "muted")}
        </div>
        <div class="hero-title mono">${esc(data.cidr)} ${copyButton(data.cidr)}</div>
        <div class="hero-sub">${esc(hostLine)}</div>
      </div>
      <div class="hero-metric">
        <span class="metric-value">${esc(data.usable_display)}</span>
        <span class="metric-label">usable hosts</span>
        <span class="metric-sub">${esc(totalLabel(data))}</span>
      </div>
    </div>
    <div class="stat-grid">${stats.join("")}</div>
    ${binaryCard(data)}
    ${notesHtml(data.notes)}`;
}

function renderRange(data) {
  const blocks = data.cidr_list || [];
  const chips = blocks
    .map(
      (block) => `
        <span class="block">${esc(block)}
          <button class="mini-copy" type="button" data-copy="${esc(block)}" aria-label="Copy ${esc(block)}">copy</button>
        </span>`
    )
    .join("");

  return `
    <div class="hero">
      <div class="hero-main">
        <div class="eyebrow">
          ${badge(`IPv${data.version}`, "info")}
          ${badge(data.scope, scopeTone(data.scope))}
          ${badge(`${data.cidr_count} CIDR blocks`, "muted")}
        </div>
        <div class="hero-title mono">
          ${esc(data.start)} <span class="hero-arrow">→</span> ${esc(data.end)}
        </div>
        <div class="hero-sub">${esc(data.total_display)} addresses${data.total_power ? ` · ${esc(data.total_power)}` : ""}</div>
      </div>
      <div class="hero-metric">
        <span class="metric-value">${esc(data.cidr_count)}</span>
        <span class="metric-label">CIDR blocks</span>
        <span class="metric-sub">${esc(data.common_prefix)} common prefix</span>
      </div>
    </div>
    <div class="stat-grid">
      ${stat("Start", data.start)}
      ${stat("End", data.end)}
      ${stat("Addresses", data.total_display, data.total_power || "")}
      ${stat("Common prefix", data.common_prefix)}
    </div>
    <div class="card block-list">
      <div class="card-head">
        <h3>CIDR blocks</h3>
        ${copyButton(blocks.join("\n"), "copy all")}
      </div>
      <div class="blocks">${chips}</div>
    </div>
    ${notesHtml(data.notes)}`;
}

function renderInspect(data) {
  return data.kind === "range" ? renderRange(data) : renderNetwork(data);
}

function renderSplit(data) {
  const isV4 = data.version === 4;
  const limit = 400;
  const tableRows = data.subnets.map((subnet) => ({
    index: subnet.index,
    cidr: subnet.cidr,
    first_host: subnet.first_host,
    last_host: subnet.last_host,
    broadcast: subnet.broadcast ?? "",
    usable: subnet.usable_display ?? "",
    size: subnet.total_power || subnet.total_display,
  }));
  const columns = isV4
    ? [
        { key: "index", label: "#" },
        { key: "cidr", label: "Network" },
        { key: "first_host", label: "First host" },
        { key: "last_host", label: "Last host" },
        { key: "broadcast", label: "Broadcast" },
        { key: "usable", label: "Usable" },
      ]
    : [
        { key: "index", label: "#" },
        { key: "cidr", label: "Network" },
        { key: "first_host", label: "First address" },
        { key: "last_host", label: "Last address" },
        { key: "size", label: "Size" },
      ];
  const shown = tableRows.slice(0, limit);
  const copyAll = copyButton(
    data.subnets.map((subnet) => subnet.cidr).join("\n"),
    "copy all"
  );
  const downloads = downloadButtons(
    "subnetkit-split",
    tableRows,
    columns,
    "Download split table"
  );

  const head = isV4
    ? "<tr><th>#</th><th>Network</th><th>Host range</th><th>Broadcast</th><th>Usable</th></tr>"
    : "<tr><th>#</th><th>Network</th><th>Address range</th><th>Size</th></tr>";

  const body = shown
    .map((subnet) =>
      isV4
        ? `<tr>
             <td class="muted-cell">${subnet.index}</td>
             <td>${esc(subnet.cidr)} ${copyButton(subnet.cidr)}</td>
             <td>${esc(subnet.first_host)} – ${esc(subnet.last_host)}</td>
             <td>${esc(subnet.broadcast)}</td>
             <td>${esc(subnet.usable)}</td>
           </tr>`
        : `<tr>
             <td class="muted-cell">${subnet.index}</td>
             <td>${esc(subnet.cidr)} ${copyButton(subnet.cidr)}</td>
             <td>${esc(subnet.first_host)} – ${esc(subnet.last_host)}</td>
             <td>${esc(subnet.size)}</td>
           </tr>`
    )
    .join("");

  const limitNote =
    data.subnets.length > limit
      ? `<div class="notes"><p>Showing the first ${limit} of ${data.subnets.length.toLocaleString()} subnets. Use “copy all” to grab every CIDR, or download the full table as CSV/JSON.</p></div>`
      : "";

  return `
    <div class="result-head">
      <div>
        <div class="eyebrow">
          ${badge(`IPv${data.version}`, "info")}
          ${badge(data.parent, "muted")}
          ${badge(`/${data.new_prefix}`, "violet")}
        </div>
        <h2>${data.generated_count.toLocaleString()} ${data.generated_count === 1 ? "subnet" : "subnets"}</h2>
      </div>
      <div class="result-actions">${downloads}${copyAll}</div>
    </div>
    <div class="table-wrap">
      <table><thead>${head}</thead><tbody>${body}</tbody></table>
    </div>
    ${limitNote}
    ${notesHtml(data.notes)}`;
}

function renderMask(data) {
  const isV4 = data.version === 4;
  const stats = [
    stat("Netmask", data.netmask),
    stat("Wildcard", data.wildcard),
    stat("Total addresses", data.total_display, data.total_power || ""),
    stat("Usable hosts", data.usable_display, isV4 ? "excluding network & broadcast" : "all addresses usable"),
  ];
  if (!isV4) stats.push(stat("Expanded mask", data.netmask_expanded, "", "span-2"));

  const maskRows = data.quick_reference || [];
  const maskDownloads = downloadButtons(
    "subnetkit-masks",
    maskRows,
    [
      { key: "prefix", label: "Prefix" },
      { key: "netmask", label: "Netmask" },
      { key: "wildcard", label: "Wildcard" },
      { key: "usable_hosts", label: "Usable hosts" },
    ],
    "Download common masks table"
  );
  const reference = maskRows.length
    ? `<div class="card">
         <div class="card-head"><h3>Common IPv4 masks</h3><div class="result-actions">${maskDownloads}</div></div>
         <div class="table-wrap">
           <table>
             <thead><tr><th>Prefix</th><th>Netmask</th><th>Wildcard</th><th>Usable hosts</th></tr></thead>
             <tbody>
               ${maskRows
                 .map(
                   (row) => `<tr>
                     <td>/${row.prefix}</td>
                     <td>${esc(row.netmask)}</td>
                     <td>${esc(row.wildcard)}</td>
                     <td>${row.usable_hosts.toLocaleString()}</td>
                   </tr>`
                 )
                 .join("")}
             </tbody>
           </table>
         </div>
       </div>`
    : "";

  return `
    <div class="hero">
      <div class="hero-main">
        <div class="eyebrow">
          ${badge(`IPv${data.version}`, "info")}
          ${badge("mask", "muted")}
          ${data.input_kind === "wildcard" ? badge("wildcard input", "warn") : ""}
        </div>
        <div class="hero-title mono">/${data.prefix} ${copyButton(`/${data.prefix}`)}</div>
        <div class="hero-sub mono">${esc(data.netmask)}</div>
      </div>
      <div class="hero-metric">
        <span class="metric-value">${esc(data.usable_display)}</span>
        <span class="metric-label">usable hosts</span>
        <span class="metric-sub">${esc(totalLabel(data))}</span>
      </div>
    </div>
    <div class="stat-grid">${stats.join("")}</div>
    ${maskBinaryCard(data)}
    ${reference}
    ${notesHtml(data.notes)}`;
}

function renderVlsm(data) {
  const tableRows = data.allocations.map((allocation) => {
    const requested = allocation.requested_hosts;
    const effective = allocation.effective_hosts ?? requested;
    const needs =
      effective !== requested
        ? `${requested.toLocaleString()} → ${effective.toLocaleString()}`
        : requested.toLocaleString();
    return {
      name: allocation.name,
      needs,
      cidr: allocation.cidr,
      host_range: `${allocation.first_host} – ${allocation.last_host}`,
      usable: allocation.usable_display,
      waste: allocation.waste_display ?? String(allocation.waste),
    };
  });
  const columns = [
    { key: "name", label: "Name" },
    { key: "needs", label: "Needs" },
    { key: "cidr", label: "Allocated" },
    { key: "host_range", label: "Host range" },
    { key: "usable", label: "Usable" },
    { key: "waste", label: "Waste" },
  ];
  const rows = tableRows
    .map(
      (allocation) => `
        <tr>
          <td>${esc(allocation.name)}</td>
          <td>${esc(allocation.needs)}</td>
          <td>${esc(allocation.cidr)} ${copyButton(allocation.cidr)}</td>
          <td>${esc(allocation.host_range)}</td>
          <td>${esc(allocation.usable)}</td>
          <td class="muted-cell">${esc(allocation.waste)}</td>
        </tr>`
    )
    .join("");

  const freeBlocks = data.free_blocks || [];
  const free = freeBlocks.length
    ? `<div class="card block-list">
         <div class="card-head"><h3>Free space</h3>${copyButton(freeBlocks.join("\n"), "copy all")}</div>
         <div class="blocks">
           ${freeBlocks
             .map(
               (block) =>
                 `<span class="block">${esc(block)}
                    <button class="mini-copy" type="button" data-copy="${esc(block)}">copy</button>
                  </span>`
             )
             .join("")}
         </div>
       </div>`
    : "";
  const map = addressMapHtml({
    parent: data.parent,
    allocations: data.allocations,
    freeBlocks,
    mode: "vlsm",
  });
  const downloads = downloadButtons(
    "subnetkit-vlsm",
    tableRows,
    columns,
    "Download VLSM table"
  );

  const optionBadges = [];
  if (data.classic) optionBadges.push(badge("classic", "muted"));
  if (data.gateway) optionBadges.push(badge("gateway reserved", "muted"));
  if (data.growth_percent) {
    optionBadges.push(badge(`growth ${data.growth_percent}%`, "muted"));
  }

  return `
    <div class="result-head">
      <div>
        <div class="eyebrow">
          ${badge(`IPv${data.version}`, "info")}
          ${badge(data.parent, "muted")}
          ${badge("largest first", "muted")}
          ${optionBadges.join("")}
        </div>
        <h2>${data.allocations.length} ${data.allocations.length === 1 ? "allocation" : "allocations"}</h2>
      </div>
      <div class="result-actions">${downloads}${copyButton(
        data.allocations.map((allocation) => allocation.cidr).join("\n"),
        "copy CIDRs"
      )}</div>
    </div>
    ${map}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>Needs</th><th>Allocated</th><th>Host range</th><th>Usable</th><th>Waste</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    ${free}
    ${notesHtml(data.notes)}`;
}

const RELATION_TONE = {
  inside: "ok",
  subnet: "ok",
  outside: "warn",
  supernet: "info",
  overlap: "warn",
  disjoint: "muted",
  "different-version": "bad",
  invalid: "bad",
  unsupported: "bad",
};

function renderCheck(data) {
  const tableRows = data.results.map((result) => ({
    input: result.input,
    relation: result.relation,
    note: result.note,
  }));
  const columns = [
    { key: "input", label: "Input" },
    { key: "relation", label: "Relation" },
    { key: "note", label: "Detail" },
  ];
  const rows = data.results
    .map(
      (result) => `
        <tr>
          <td>${esc(result.input)}</td>
          <td>${badge(result.relation.replace("-", " "), RELATION_TONE[result.relation] || "muted")}</td>
          <td class="note-cell">${esc(result.note)}</td>
        </tr>`
    )
    .join("");
  const downloads = downloadButtons(
    "subnetkit-check",
    tableRows,
    columns,
    "Download checks table"
  );

  return `
    <div class="result-head">
      <div>
        <div class="eyebrow">
          ${badge(`IPv${data.version}`, "info")}
          ${badge("base", "muted")}
          ${badge(data.base, "violet")}
        </div>
        <h2>${data.results.length} ${data.results.length === 1 ? "check" : "checks"}</h2>
      </div>
      <div class="result-actions">${downloads}</div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Input</th><th>Relation</th><th>Detail</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="3" class="muted-cell">No values to check.</td></tr>`}</tbody>
      </table>
    </div>`;
}

/* ------------------------------------------------------------------ */
/* Planner renderers                                                   */
/* ------------------------------------------------------------------ */

function planBlockChips(blocks, emptyMessage = "No blocks.") {
  if (!blocks || !blocks.length) return emptyHtml(emptyMessage);
  return `<div class="blocks">${blocks
    .map(
      (block) =>
        `<span class="block">${esc(block)}
           <button class="mini-copy" type="button" data-copy="${esc(block)}">copy</button>
         </span>`
    )
    .join("")}</div>`;
}

function planFreeCard(free) {
  if (!free) return "";
  return `
    <div class="card block-list">
      <div class="card-head">
        <h3>Free space</h3>
        ${copyButton((free.free_blocks || []).join("\n"), "copy all")}
      </div>
      <div class="stat-grid plan-mini-stats">
        ${stat("Free blocks", free.free_count ?? 0)}
        ${stat("Free addresses", free.free_display ?? "0")}
        ${stat("Allocated", free.allocated_display ?? "0")}
      </div>
      ${planBlockChips(free.free_blocks, "No free space remains.")}
      ${notesHtml(free.notes)}
    </div>`;
}

function planValidationCard(validation) {
  if (!validation || validation.valid) {
    return validation
      ? `<div class="plan-valid">${badge("valid", "ok")} No overlaps, outside blocks, or duplicate names/VLANs.</div>`
      : "";
  }
  const errorRows = validation.errors.map((error) => ({
    index: error.index ?? "",
    code: error.code,
    message: error.message,
  }));
  const columns = [
    { key: "index", label: "#" },
    { key: "code", label: "Code" },
    { key: "message", label: "Detail" },
  ];
  const rows = errorRows
    .map(
      (error) => `
        <tr>
          <td class="muted-cell">${esc(error.index)}</td>
          <td>${badge(error.code, "bad")}</td>
          <td class="note-cell">${esc(error.message)}</td>
        </tr>`
    )
    .join("");
  const downloads = downloadButtons(
    "subnetkit-plan-validation",
    errorRows,
    columns,
    "Download validation table"
  );
  return `
    <div class="card plan-validation">
      <div class="card-head">
        <h3>Validation</h3>
        <div class="result-actions">
          ${badge(`${validation.errors.length} issue${validation.errors.length === 1 ? "" : "s"}`, "bad")}
          ${downloads}
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>#</th><th>Code</th><th>Detail</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
}

function planTable(subnets) {
  if (!subnets.length) {
    return emptyHtml("No subnets yet. Add one above using best-fit free space.");
  }
  const rows = subnets
    .map(
      (entry) => `
        <tr>
          <td>${esc(entry.name)}</td>
          <td>${esc(entry.cidr)} ${copyButton(entry.cidr)}</td>
          <td class="muted-cell">${entry.vlan === null || entry.vlan === undefined ? "—" : esc(entry.vlan)}</td>
          <td class="note-cell">${esc(entry.notes || "")}</td>
        </tr>`
    )
    .join("");
  return `
    <div class="table-wrap">
      <table>
        <thead><tr><th>Name</th><th>CIDR</th><th>VLAN</th><th>Notes</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function renderPlanView(plan, options = {}) {
  const subnets = plan.subnets || [];
  const free = options.free || plan.free || null;
  const validation = options.validation || plan.validation || null;
  const freeBlocks = free?.free_blocks || [];
  const downloads = downloadButtons(
    "subnetkit-plan",
    subnets,
    [
      { key: "name", label: "Name" },
      { key: "cidr", label: "CIDR" },
      { key: "vlan", label: "VLAN" },
      { key: "notes", label: "Notes" },
    ],
    "Download plan table"
  );
  const map = addressMapHtml({
    parent: plan.parent,
    allocations: subnets,
    freeBlocks,
    mode: "plan",
  });
  return `
    <div class="result-head">
      <div>
        <div class="eyebrow">
          ${badge("plan", "info")}
          ${badge(plan.parent, "violet")}
          ${badge(`${subnets.length} ${subnets.length === 1 ? "subnet" : "subnets"}`, "muted")}
          ${validation && validation.valid ? badge("valid", "ok") : ""}
        </div>
        <h2>${esc(plan.parent)}</h2>
      </div>
      <div class="result-actions">${downloads}${copyButton(
        subnets.map((entry) => entry.cidr).join("\n"),
        "copy CIDRs"
      )}</div>
    </div>
    ${map}
    ${planTable(subnets)}
    ${planFreeCard(free)}
    ${planValidationCard(validation)}`;
}

function renderPlanAdd(data) {
  return `
    <div class="result-head">
      <div>
        <div class="eyebrow">
          ${badge("added", "ok")}
          ${badge(data.name, "muted")}
          ${data.vlan === null || data.vlan === undefined ? "" : badge(`VLAN ${data.vlan}`, "violet")}
        </div>
        <h2>${esc(data.name)} → <span class="mono">${esc(data.cidr)}</span></h2>
      </div>
      ${copyButton(data.cidr, "copy CIDR")}
    </div>
    ${renderPlanView(data.plan, {
      free: data.free,
      validation: data.validation,
    })}`;
}

function renderPlanFree(data, plan = null) {
  const map = plan
    ? addressMapHtml({
        parent: data.parent,
        allocations: plan.subnets || [],
        freeBlocks: data.free_blocks || [],
        mode: "plan",
      })
    : "";
  return `
    <div class="result-head">
      <div>
        <div class="eyebrow">
          ${badge("free space", "info")}
          ${badge(data.parent, "violet")}
          ${badge(`${data.free_count} ${data.free_count === 1 ? "block" : "blocks"}`, "muted")}
        </div>
        <h2>${esc(data.free_display)} addresses free</h2>
      </div>
      ${copyButton((data.free_blocks || []).join("\n"), "copy blocks")}
    </div>
    ${map}
    <div class="card block-list">
      <div class="card-head"><h3>Remaining blocks</h3></div>
      ${planBlockChips(data.free_blocks, "No free space remains.")}
      ${notesHtml(data.notes)}
    </div>`;
}

function renderPlanValidation(data, plan = null, free = null) {
  const map = plan
    ? addressMapHtml({
        parent: data.parent || plan.parent,
        allocations: plan.subnets || [],
        freeBlocks: free?.free_blocks || [],
        mode: "plan",
      })
    : "";
  return `
    <div class="result-head">
      <div>
        <div class="eyebrow">
          ${badge("validate", "info")}
          ${badge(data.parent, "violet")}
          ${badge(data.valid ? "valid" : "invalid", data.valid ? "ok" : "bad")}
        </div>
        <h2>${data.valid ? "Plan is valid" : `${data.errors.length} validation issue${data.errors.length === 1 ? "" : "s"}`}</h2>
      </div>
    </div>
    ${map}
    ${planValidationCard(data)}`;
}

function renderPlanExport(data) {
  return `
    <div class="card plan-export-card">
      <div class="card-head">
        <h3>${esc(data.format)} export</h3>
        ${copyButton(data.text, "copy")}
      </div>
      <textarea class="export-text mono" readonly rows="${Math.min(18, Math.max(5, data.text.split("\n").length))}" spellcheck="false">${esc(data.text)}</textarea>
    </div>`;
}

/* ------------------------------------------------------------------ */
/* Inspect tab                                                         */
/* ------------------------------------------------------------------ */

const inspectInput = $("#inspect-input");
const inspectOut = $("#inspect-out");
let inspectSequence = 0;
let inspectTimer = null;

async function runInspect() {
  const value = inspectInput.value.trim();
  if (!value) {
    inspectOut.innerHTML = emptyHtml("Enter an IP, CIDR block, or range.");
    return;
  }
  const sequence = ++inspectSequence;
  const resultState = { q: inspectInput.value };
  if (!inspectOut.innerHTML.trim()) inspectOut.innerHTML = loadingHtml();
  inspectOut.classList.add("pending");
  try {
    const data = await post("/api/inspect", { input: value });
    if (sequence !== inspectSequence) return;
    inspectOut.innerHTML = renderInspect(data);
    rememberResult("inspect", resultState);
  } catch (error) {
    if (sequence !== inspectSequence) return;
    inspectOut.innerHTML = errorHtml(error.message);
  } finally {
    if (sequence === inspectSequence) inspectOut.classList.remove("pending");
  }
}

inspectInput.addEventListener("input", () => {
  clearTimeout(inspectTimer);
  inspectTimer = setTimeout(runInspect, 320);
});
inspectInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    clearTimeout(inspectTimer);
    runInspect();
  }
});
$("#inspect-go").addEventListener("click", () => {
  clearTimeout(inspectTimer);
  runInspect();
});

$$("[data-example]").forEach((button) => {
  button.addEventListener("click", () => {
    inspectInput.value = button.dataset.example;
    inspectInput.focus();
    clearTimeout(inspectTimer);
    runInspect();
  });
});

/* ------------------------------------------------------------------ */
/* Split tab                                                           */
/* ------------------------------------------------------------------ */

const splitInput = $("#split-target");
const splitMode = $("#split-mode");
const splitValue = $("#split-value");
const splitValueLabel = $("#split-value-label");
const splitOut = $("#split-out");
const splitGo = $("#split-go");
let splitLoaded = false;

function updateSplitMode() {
  const prefixMode = splitMode.value === "prefix";
  splitValueLabel.textContent = prefixMode ? "New prefix" : "Count";
  splitValue.min = prefixMode ? "0" : "1";
  splitValue.max = prefixMode ? "128" : "4096";
  if (prefixMode && splitValue.value === "4") splitValue.value = "26";
  if (!prefixMode && splitValue.value === "26") splitValue.value = "4";
}

async function runSplit() {
  splitLoaded = true;
  const target = splitInput.value.trim();
  if (!target) {
    splitOut.innerHTML = emptyHtml("Enter a parent network in CIDR form.");
    return;
  }
  const body = { target };
  const resultState = readInputState("split");
  const rawValue = splitValue.value.trim();
  if (splitMode.value === "prefix") {
    body.prefix = rawValue;
  } else {
    body.count = rawValue;
  }
  splitGo.disabled = true;
  const label = splitGo.textContent;
  splitGo.textContent = "Splitting…";
  splitOut.classList.add("pending");
  try {
    const data = await post("/api/split", body);
    splitOut.innerHTML = renderSplit(data);
    rememberResult("split", resultState);
  } catch (error) {
    splitOut.innerHTML = errorHtml(error.message);
  } finally {
    splitGo.disabled = false;
    splitGo.textContent = label;
    splitOut.classList.remove("pending");
  }
}

splitMode.addEventListener("change", updateSplitMode);
splitGo.addEventListener("click", runSplit);
[splitInput, splitValue].forEach((element) => {
  element.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      runSplit();
    }
  });
});

/* ------------------------------------------------------------------ */
/* Mask tab                                                            */
/* ------------------------------------------------------------------ */

const maskInput = $("#mask-input");
const maskVersion = $("#mask-version");
const maskOut = $("#mask-out");
const maskGo = $("#mask-go");
let maskLoaded = false;

async function runMask() {
  maskLoaded = true;
  const mask = maskInput.value.trim();
  const resultState = readInputState("mask");
  if (!mask) {
    maskOut.innerHTML = emptyHtml("Enter a netmask or prefix length.");
    return;
  }
  maskGo.disabled = true;
  const label = maskGo.textContent;
  maskGo.textContent = "Converting…";
  maskOut.classList.add("pending");
  try {
    const data = await post("/api/mask", {
      mask,
      version: Number(maskVersion.value),
    });
    maskOut.innerHTML = renderMask(data);
    rememberResult("mask", resultState);
  } catch (error) {
    maskOut.innerHTML = errorHtml(error.message);
  } finally {
    maskGo.disabled = false;
    maskGo.textContent = label;
    maskOut.classList.remove("pending");
  }
}

function applyMaskExample(button) {
  maskInput.value = button.dataset.mask;
  if (button.dataset.version) maskVersion.value = button.dataset.version;
  maskLoaded = true;
  runMask();
}

$$("[data-mask]").forEach((button) => {
  button.addEventListener("click", () => applyMaskExample(button));
});

maskInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    runMask();
  }
});
maskGo.addEventListener("click", runMask);
maskVersion.addEventListener("change", () => {
  if (maskLoaded) runMask();
});

/* ------------------------------------------------------------------ */
/* VLSM tab                                                            */
/* ------------------------------------------------------------------ */

const vlsmInput = $("#vlsm-target");
const vlsmReqs = $("#vlsm-reqs");
const vlsmClassic = $("#vlsm-classic");
const vlsmGateway = $("#vlsm-gateway");
const vlsmGrowth = $("#vlsm-growth");
const vlsmOut = $("#vlsm-out");
const vlsmGo = $("#vlsm-go");
let vlsmLoaded = false;

async function runVlsm() {
  vlsmLoaded = true;
  const target = vlsmInput.value.trim();
  const resultState = readInputState("vlsm");
  if (!target) {
    vlsmOut.innerHTML = emptyHtml("Enter a parent network in CIDR form.");
    return;
  }
  vlsmGo.disabled = true;
  const label = vlsmGo.textContent;
  vlsmGo.textContent = "Allocating…";
  vlsmOut.classList.add("pending");
  try {
    const data = await post("/api/vlsm", {
      target,
      requirements: vlsmReqs.value,
      classic: vlsmClassic.checked,
      gateway: vlsmGateway.checked,
      growth: vlsmGrowth.value,
    });
    vlsmOut.innerHTML = renderVlsm(data);
    rememberResult("vlsm", resultState);
  } catch (error) {
    vlsmOut.innerHTML = errorHtml(error.message);
  } finally {
    vlsmGo.disabled = false;
    vlsmGo.textContent = label;
    vlsmOut.classList.remove("pending");
  }
}

vlsmGo.addEventListener("click", runVlsm);
vlsmInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    runVlsm();
  }
});
vlsmReqs.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
    event.preventDefault();
    runVlsm();
  }
});

/* ------------------------------------------------------------------ */
/* Check tab                                                           */
/* ------------------------------------------------------------------ */

const checkInput = $("#check-target");
const checkOthers = $("#check-others");
const checkOut = $("#check-out");
const checkGo = $("#check-go");
let checkLoaded = false;

async function runCheck() {
  checkLoaded = true;
  const target = checkInput.value.trim();
  const resultState = readInputState("check");
  if (!target) {
    checkOut.innerHTML = emptyHtml("Enter a base network in CIDR form.");
    return;
  }
  checkGo.disabled = true;
  const label = checkGo.textContent;
  checkGo.textContent = "Checking…";
  checkOut.classList.add("pending");
  try {
    const data = await post("/api/check", {
      target,
      others: checkOthers.value,
    });
    checkOut.innerHTML = renderCheck(data);
    rememberResult("check", resultState);
  } catch (error) {
    checkOut.innerHTML = errorHtml(error.message);
  } finally {
    checkGo.disabled = false;
    checkGo.textContent = label;
    checkOut.classList.remove("pending");
  }
}

checkGo.addEventListener("click", runCheck);
checkInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    runCheck();
  }
});
checkOthers.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
    event.preventDefault();
    runCheck();
  }
});

/* ------------------------------------------------------------------ */
/* Planner tab                                                         */
/* ------------------------------------------------------------------ */

const planParent = $("#plan-parent");
const planName = $("#plan-name");
const planHosts = $("#plan-hosts");
const planVlan = $("#plan-vlan");
const planClassic = $("#plan-classic");
const planGateway = $("#plan-gateway");
const planOut = $("#plan-out");
const planExportOut = $("#plan-export-out");
const planStatus = $("#plan-status");
const planNewButton = $("#plan-new");
const planAddButton = $("#plan-add");
const planValidateButton = $("#plan-validate");
const planFreeButton = $("#plan-free");
const planExportButton = $("#plan-export");
const planExportFormat = $("#plan-export-format");

let planState = null;
let planBusy = false;
let planViewMode = "show";
let planLastAdded = null;
let planExportDone = false;
let planExportedFormat = null;

function setPlanStatus(message) {
  planStatus.textContent = message;
}

function setPlanBusy(busy) {
  planBusy = busy;
  [planNewButton, planAddButton, planValidateButton, planFreeButton, planExportButton].forEach(
    (button) => {
      button.disabled = busy;
    }
  );
}

function requirePlan() {
  if (planState) return true;
  planOut.innerHTML = emptyHtml("Create a plan first using the parent network above.");
  return false;
}

function showPlanView(data) {
  planOut.innerHTML = renderPlanView(data);
}

async function runPlanInit() {
  if (planBusy) return;
  const parent = planParent.value.trim();
  if (!parent) {
    planOut.innerHTML = emptyHtml("Enter a parent network in CIDR form.");
    return;
  }
  setPlanBusy(true);
  planOut.innerHTML = loadingHtml();
  try {
    const created = await post("/api/plan/init", { parent });
    const view = await post("/api/plan/show", { plan: created });
    planState = created;
    planParent.value = created.parent;
    planViewMode = "show";
    planLastAdded = null;
    planExportDone = false;
    planExportedFormat = null;
    showPlanView(view);
    planExportOut.innerHTML = "";
    setPlanStatus(`Plan ready · ${created.parent}`);
    syncPlanHash();
  } catch (error) {
    planState = null;
    planViewMode = "show";
    planLastAdded = null;
    planExportDone = false;
    planExportedFormat = null;
    planOut.innerHTML = errorHtml(error.message);
    setPlanStatus("No plan loaded.");
    syncPlanHash(null);
  } finally {
    setPlanBusy(false);
  }
}

async function runPlanAdd() {
  if (!requirePlan() || planBusy) return;
  const name = planName.value.trim();
  const hosts = planHosts.value.trim();
  if (!name) {
    planOut.innerHTML = emptyHtml("Enter a subnet name.");
    return;
  }
  if (!hosts) {
    planOut.innerHTML = emptyHtml("Enter a host count.");
    return;
  }
  setPlanBusy(true);
  planOut.classList.add("pending");
  try {
    const body = {
      plan: planState,
      name,
      hosts,
      classic: planClassic.checked,
      gateway: planGateway.checked,
    };
    const vlan = planVlan.value.trim();
    if (vlan !== "") body.vlan = vlan;
    const data = await post("/api/plan/add", body);
    planState = data.plan;
    planViewMode = "add";
    planLastAdded = {
      name: data.name,
      cidr: data.cidr,
      vlan: data.vlan,
      notes: data.notes,
    };
    planExportDone = false;
    planExportedFormat = null;
    planOut.innerHTML = renderPlanAdd(data);
    planExportOut.innerHTML = "";
    setPlanStatus(`${data.name} → ${data.cidr}`);
    planName.value = "";
    planName.focus();
    syncPlanHash();
  } catch (error) {
    planOut.innerHTML = errorHtml(error.message);
  } finally {
    planOut.classList.remove("pending");
    setPlanBusy(false);
  }
}

async function runPlanValidate() {
  if (!requirePlan() || planBusy) return;
  setPlanBusy(true);
  planOut.classList.add("pending");
  try {
    const [data, free] = await Promise.all([
      post("/api/plan/validate", { plan: planState }),
      post("/api/plan/free", { plan: planState }).catch(() => null),
    ]);
    planViewMode = "validate";
    planOut.innerHTML = renderPlanValidation(data, planState, free);
    setPlanStatus(
      data.valid
        ? "Plan is valid."
        : `${data.errors.length} validation issue${data.errors.length === 1 ? "" : "s"}.`
    );
    syncPlanHash();
  } catch (error) {
    planOut.innerHTML = errorHtml(error.message);
  } finally {
    planOut.classList.remove("pending");
    setPlanBusy(false);
  }
}

async function runPlanFree() {
  if (!requirePlan() || planBusy) return;
  setPlanBusy(true);
  planOut.classList.add("pending");
  try {
    const data = await post("/api/plan/free", { plan: planState });
    planViewMode = "free";
    planOut.innerHTML = renderPlanFree(data, planState);
    setPlanStatus(`${data.free_count} free block${data.free_count === 1 ? "" : "s"}.`);
    syncPlanHash();
  } catch (error) {
    planOut.innerHTML = errorHtml(error.message);
  } finally {
    planOut.classList.remove("pending");
    setPlanBusy(false);
  }
}

async function runPlanExport() {
  if (!requirePlan() || planBusy) return;
  setPlanBusy(true);
  planExportOut.classList.add("pending");
  try {
    const data = await post("/api/plan/export", {
      plan: planState,
      format: planExportFormat.value,
    });
    planExportDone = true;
    planExportedFormat = data.format;
    planExportOut.innerHTML = renderPlanExport(data);
    setPlanStatus(`Exported as ${data.format}.`);
    syncPlanHash();
  } catch (error) {
    planExportDone = false;
    planExportedFormat = null;
    planExportOut.innerHTML = errorHtml(error.message);
    syncPlanHash();
  } finally {
    planExportOut.classList.remove("pending");
    setPlanBusy(false);
  }
}

planNewButton.addEventListener("click", runPlanInit);
planAddButton.addEventListener("click", runPlanAdd);
planValidateButton.addEventListener("click", runPlanValidate);
planFreeButton.addEventListener("click", runPlanFree);
planExportButton.addEventListener("click", runPlanExport);
[planParent, planName, planHosts, planVlan].forEach((element) => {
  element.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    if (element === planParent) runPlanInit();
    else runPlanAdd();
  });
});
setPlanStatus("Create a plan to begin.");
planOut.innerHTML = emptyHtml("Create a plan to begin.");

/* ------------------------------------------------------------------ */
/* Tabs                                                                */
/* ------------------------------------------------------------------ */

const TABS = ["inspect", "split", "mask", "vlsm", "check", "plan"];
const loaded = {
  inspect: true,
  split: false,
  mask: false,
  vlsm: false,
  check: false,
  plan: true,
};

function activateTab(name, updateHash = true, run = true) {
  if (!TABS.includes(name)) name = "inspect";
  activeTab = name;
  $$(".tab").forEach((tab) => {
    const active = tab.dataset.tab === name;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  $$(".panel").forEach((panel) => {
    const active = panel.id === `panel-${name}`;
    panel.classList.toggle("active", active);
    panel.hidden = !active;
  });
  if (updateHash) {
    const state =
      name === "plan" ? readInputState(name) : resultStates[name] || readInputState(name);
    writeHash(name, state);
  }
  if (name !== "inspect") clearTimeout(inspectTimer);
  if (!run) return;

  if (name === "inspect") {
    runInspect();
  } else if (!loaded[name]) {
    loaded[name] = true;
    if (name === "split") runSplit();
    if (name === "mask") runMask();
    if (name === "vlsm") runVlsm();
    if (name === "check") runCheck();
  }
}

const tabButtons = $$(".tab");
tabButtons.forEach((tab, index) => {
  tab.addEventListener("click", () => activateTab(tab.dataset.tab));
  tab.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    let next = index;
    if (event.key === "ArrowLeft") next = (index - 1 + tabButtons.length) % tabButtons.length;
    if (event.key === "ArrowRight") next = (index + 1) % tabButtons.length;
    if (event.key === "Home") next = 0;
    if (event.key === "End") next = tabButtons.length - 1;
    tabButtons[next].focus();
    activateTab(tabButtons[next].dataset.tab);
  });
});

function runTab(name) {
  if (name === "plan") return restorePlanFromHash();
  if (name === "inspect") return runInspect();
  if (name === "split") return runSplit();
  if (name === "mask") return runMask();
  if (name === "vlsm") return runVlsm();
  if (name === "check") return runCheck();
  return null;
}

/* ------------------------------------------------------------------ */
/* Copy + toast                                                        */
/* ------------------------------------------------------------------ */

let toastTimer = null;

function toast(message) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.remove("show"), 1600);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (error) {
    const area = document.createElement("textarea");
    area.value = text;
    area.className = "copy-proxy";
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand("copy");
    } catch (fallbackError) {
      toast("Copy failed");
      area.remove();
      return;
    }
    area.remove();
  }
  toast("Copied to clipboard");
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  copyText(button.dataset.copy);
});

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-download-id]");
  if (!button) return;
  const entry = downloadStore.get(button.dataset.downloadId);
  if (!entry) {
    toast("Download is no longer available. Re-run the result.");
    return;
  }
  try {
    const payload = downloadPayload(entry, button.dataset.format);
    triggerDownload(
      `${entry.filename}.${payload.extension}`,
      payload.text,
      payload.type
    );
    toast(`${button.dataset.format.toUpperCase()} downloaded`);
  } catch (error) {
    toast("Download failed");
  }
});

const MAP_READOUT_DEFAULT = "Hover or focus a map block for details.";

function updateMapReadout(target, reset = false) {
  const map = target.closest(".address-map");
  if (!map) return;
  const readout = $(".map-readout", map);
  if (!readout) return;
  readout.textContent = reset
    ? MAP_READOUT_DEFAULT
    : target.getAttribute("data-map-tip") || MAP_READOUT_DEFAULT;
}

document.addEventListener("pointerover", (event) => {
  const target = event.target.closest("[data-map-tip]");
  if (target) updateMapReadout(target);
});

document.addEventListener("focusin", (event) => {
  const target = event.target.closest("[data-map-tip]");
  if (target) updateMapReadout(target);
});

document.addEventListener("pointerout", (event) => {
  const target = event.target.closest("[data-map-tip]");
  if (!target) return;
  const related = event.relatedTarget;
  if (related && related.closest && related.closest("[data-map-tip]")) return;
  updateMapReadout(target, true);
});

document.addEventListener("focusout", (event) => {
  const target = event.target.closest("[data-map-tip]");
  if (!target) return;
  const related = event.relatedTarget;
  if (related && related.closest && related.closest("[data-map-tip]")) return;
  updateMapReadout(target, true);
});

/* ------------------------------------------------------------------ */
/* Boot                                                                */
/* ------------------------------------------------------------------ */

const boot = parseHashState();
const bootApplied = boot.state ? applyTabState(boot.tab, boot.state) : false;
activateTab(boot.tab, false, !bootApplied);
if (bootApplied) runTab(boot.tab);

window.addEventListener("hashchange", () => {
  const next = parseHashState();
  const applied = next.state ? applyTabState(next.tab, next.state) : false;
  activateTab(next.tab, false, !applied);
  if (applied) runTab(next.tab);
});

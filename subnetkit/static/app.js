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
  stats.push(stat("Netmask", data.netmask, `/${data.prefix}`));
  stats.push(stat("Wildcard", data.wildcard));
  stats.push(stat("Network", data.network_address));
  stats.push(stat(isV4 ? "Broadcast" : "Last address", data.broadcast || data.last_host));
  stats.push(stat("Host range", `${data.first_host} – ${data.last_host}`, "", "span-2"));
  stats.push(stat("Usable hosts", data.usable_display, "addresses you can assign"));
  if (isV4 && data.class) stats.push(stat("Class", data.class, "historical classful class"));
  if (!isV4) stats.push(stat("Expanded mask", data.netmask_expanded, "", "span-2"));

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
  const shown = data.subnets.slice(0, limit);
  const copyAll = copyButton(
    data.subnets.map((subnet) => subnet.cidr).join("\n"),
    "copy all"
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
             <td>${esc(subnet.usable_display)}</td>
           </tr>`
        : `<tr>
             <td class="muted-cell">${subnet.index}</td>
             <td>${esc(subnet.cidr)} ${copyButton(subnet.cidr)}</td>
             <td>${esc(subnet.first_host)} – ${esc(subnet.last_host)}</td>
             <td>${esc(subnet.total_power || subnet.total_display)}</td>
           </tr>`
    )
    .join("");

  const limitNote =
    data.subnets.length > limit
      ? `<div class="notes"><p>Showing the first ${limit} of ${data.subnets.length.toLocaleString()} subnets. Use “copy all” to grab every CIDR.</p></div>`
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
      ${copyAll}
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

  const reference =
    data.quick_reference && data.quick_reference.length
      ? `<div class="card">
           <div class="card-head"><h3>Common IPv4 masks</h3></div>
           <div class="table-wrap">
             <table>
               <thead><tr><th>Prefix</th><th>Netmask</th><th>Wildcard</th><th>Usable hosts</th></tr></thead>
               <tbody>
                 ${data.quick_reference
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
  const rows = data.allocations
    .map(
      (allocation) => `
        <tr>
          <td>${esc(allocation.name)}</td>
          <td>${allocation.requested_hosts.toLocaleString()}</td>
          <td>${esc(allocation.cidr)} ${copyButton(allocation.cidr)}</td>
          <td>${esc(allocation.first_host)} – ${esc(allocation.last_host)}</td>
          <td>${esc(allocation.usable_display)}</td>
          <td class="muted-cell">${esc(allocation.waste_display ?? allocation.waste.toLocaleString())}</td>
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

  return `
    <div class="result-head">
      <div>
        <div class="eyebrow">
          ${badge(`IPv${data.version}`, "info")}
          ${badge(data.parent, "muted")}
          ${badge("largest first", "muted")}
        </div>
        <h2>${data.allocations.length} ${data.allocations.length === 1 ? "allocation" : "allocations"}</h2>
      </div>
      ${copyButton(
        data.allocations.map((allocation) => allocation.cidr).join("\n"),
        "copy CIDRs"
      )}
    </div>
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
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Input</th><th>Relation</th><th>Detail</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="3" class="muted-cell">No values to check.</td></tr>`}</tbody>
      </table>
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
  if (!inspectOut.innerHTML.trim()) inspectOut.innerHTML = loadingHtml();
  inspectOut.classList.add("pending");
  try {
    const data = await post("/api/inspect", { input: value });
    if (sequence !== inspectSequence) return;
    inspectOut.innerHTML = renderInspect(data);
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
const vlsmOut = $("#vlsm-out");
const vlsmGo = $("#vlsm-go");
let vlsmLoaded = false;

async function runVlsm() {
  vlsmLoaded = true;
  const target = vlsmInput.value.trim();
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
    });
    vlsmOut.innerHTML = renderVlsm(data);
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
/* Tabs                                                                */
/* ------------------------------------------------------------------ */

const TABS = ["inspect", "split", "mask", "vlsm", "check"];
const loaded = {
  inspect: true,
  split: false,
  mask: false,
  vlsm: false,
  check: false,
};

function activateTab(name, updateHash = true) {
  if (!TABS.includes(name)) name = "inspect";
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
  if (updateHash) history.replaceState(null, "", `#${name}`);

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

$$(".tab").forEach((tab) => {
  tab.addEventListener("click", () => activateTab(tab.dataset.tab));
});

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
    area.style.position = "fixed";
    area.style.opacity = "0";
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

/* ------------------------------------------------------------------ */
/* Boot                                                                */
/* ------------------------------------------------------------------ */

const initial = location.hash.replace("#", "");
activateTab(TABS.includes(initial) ? initial : "inspect", false);

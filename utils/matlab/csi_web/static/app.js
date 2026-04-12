/* global fetch, URLSearchParams */

const $ = (id) => document.getElementById(id);

let browseRelPath = "";
let lastFileId = "";
/** @type {File | null} PCAP elegido desde una carpeta local (modo subir carpeta) */
let pendingFolderPcap = null;

/** @type {{ kind: "json", body: object } | { kind: "local", file: File } | null} */
let summaryContext = null;

let absoluteSummaryTimer = null;

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function escapeHtmlAttr(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;");
}

function clearFileSummary() {
  summaryContext = null;
  const wrap = $("file-summary");
  const content = $("file-summary-content");
  if (!wrap || !content) return;
  wrap.classList.add("hidden");
  content.innerHTML = "";
}

function showSummaryLoading() {
  const wrap = $("file-summary");
  const content = $("file-summary-content");
  wrap.classList.remove("hidden");
  content.innerHTML =
    '<p class="file-summary__loading">Analizando el PCAP… (puede tardar en ficheros grandes)</p>';
}

function renderSummaryError(msg) {
  const wrap = $("file-summary");
  const content = $("file-summary-content");
  wrap.classList.remove("hidden");
  content.innerHTML = `<p class="file-summary__err">${escapeHtml(msg)}</p>`;
}

function renderSummaryData(data) {
  const wrap = $("file-summary");
  const content = $("file-summary-content");
  wrap.classList.remove("hidden");

  const durText =
    data.duration_seconds != null
      ? `${Number(data.duration_seconds).toLocaleString()} s`
      : "—";

  const rateText =
    data.avg_csi_packets_per_second != null
      ? Number(data.avg_csi_packets_per_second).toLocaleString(undefined, {
          minimumFractionDigits: 0,
          maximumFractionDigits: 2,
        })
      : "—";

  const durTitle = data.duration_note ? escapeHtmlAttr(data.duration_note) : "";

  content.innerHTML = `<dl class="file-summary__dl">
      <dt>Fichero</dt><dd>${escapeHtml(data.file_name)}</dd>
      <dt>Paquetes CSI capturados</dt><dd>${Number(data.csi_packets_valid).toLocaleString()}</dd>
      <dt>Duración captura</dt><dd${durTitle ? ` title="${durTitle}"` : ""}>${durText}</dd>
      <dt>Paquetes/s</dt><dd>${rateText}</dd>
    </dl>`;
}

async function fetchSummaryJson(body) {
  showSummaryLoading();
  const payload = { ...body };
  try {
    const res = await fetch("/api/file-summary", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = data.detail;
      const msg =
        typeof detail === "string"
          ? detail
          : Array.isArray(detail)
            ? detail.map((d) => d.msg || d).join("; ")
          : res.statusText;
      renderSummaryError(msg || "Error al analizar el fichero");
      return;
    }
    renderSummaryData(data);
  } catch (e) {
    renderSummaryError(e instanceof Error ? e.message : "Error de red");
  }
}

async function fetchSummaryLocal(file) {
  showSummaryLoading();
  const fd = new FormData();
  fd.append("file", file, file.name);
  try {
    const res = await fetch("/api/file-summary-local", { method: "POST", body: fd });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = data.detail;
      const msg =
        typeof detail === "string"
          ? detail
          : Array.isArray(detail)
            ? detail.map((d) => d.msg || d).join("; ")
          : res.statusText;
      renderSummaryError(msg || "Error al analizar el fichero");
      return;
    }
    renderSummaryData(data);
  } catch (e) {
    renderSummaryError(e instanceof Error ? e.message : "Error de red");
  }
}

function scheduleAbsoluteSummary() {
  clearTimeout(absoluteSummaryTimer);
  absoluteSummaryTimer = setTimeout(() => {
    void tryAbsoluteSummary();
  }, 450);
}

function tryAbsoluteSummary() {
  if ($("mode").value !== "absolute") return;
  const p = $("absolute-path").value.trim();
  if (p.length < 5 || !/\.pcap$/i.test(p)) {
    clearFileSummary();
    return;
  }
  summaryContext = {
    kind: "json",
    body: {
      mode: "absolute",
      absolute_path: p,
      browse_relative_path: "",
      file_id: "",
    },
  };
  void fetchSummaryJson(summaryContext.body);
}

function showError(msg) {
  const el = $("error-msg");
  el.textContent = msg || "";
  el.classList.toggle("hidden", !msg);
}

function getUploadSource() {
  const r = document.querySelector('input[name="upload-source"]:checked');
  return r ? r.value : "file";
}

function syncUploadSubpanels() {
  const fromFolder = getUploadSource() === "folder";
  $("upload-single-wrap").classList.toggle("hidden", fromFolder);
  $("upload-folder-wrap").classList.toggle("hidden", !fromFolder);
}

function resetFolderUploadUi() {
  pendingFolderPcap = null;
  $("upload-folder").value = "";
  $("upload-folder-list").innerHTML = "";
  $("upload-folder-selected").textContent = "";
}

function resetSingleFileUploadUi() {
  $("upload-file").value = "";
}

function setModePanels() {
  const mode = $("mode").value;
  clearFileSummary();
  $("browse-panel").classList.toggle("hidden", mode !== "browse");
  $("upload-panel").classList.toggle("hidden", mode !== "upload");
  $("absolute-panel").classList.toggle("hidden", mode !== "absolute");
  if (mode === "upload") {
    syncUploadSubpanels();
  }
  if (mode === "absolute") {
    scheduleAbsoluteSummary();
  }
}

async function loadBrowse(path) {
  showError("");
  const q = path ? `?path=${encodeURIComponent(path)}` : "";
  const res = await fetch(`/api/browse${q}`);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    showError(data.detail || res.statusText || "Error al listar");
    return;
  }
  browseRelPath = data.path || "";
  $("browse-path").textContent = browseRelPath || "(raíz)";
  const ul = $("browse-list");
  ul.innerHTML = "";

  for (const d of data.directories || []) {
    const li = document.createElement("li");
    const span = document.createElement("span");
    span.className = "name";
    span.textContent = `${d}/`;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "secondary";
    btn.textContent = "Abrir";
    btn.addEventListener("click", () => {
      const next = browseRelPath ? `${browseRelPath}/${d}` : d;
      loadBrowse(next);
    });
    li.appendChild(span);
    li.appendChild(btn);
    ul.appendChild(li);
  }

  for (const f of data.pcaps || []) {
    const li = document.createElement("li");
    const span = document.createElement("span");
    span.className = "name";
    span.textContent = f;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "secondary";
    btn.textContent = "Usar";
    btn.addEventListener("click", () => {
      const rel = browseRelPath ? `${browseRelPath}/${f}` : f;
      $("browse-relative-path").value = rel;
      summaryContext = {
        kind: "json",
        body: {
          mode: "browse",
          browse_relative_path: rel,
          file_id: "",
          absolute_path: "",
        },
      };
      void fetchSummaryJson(summaryContext.body);
    });
    li.appendChild(span);
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

function parentBrowsePath() {
  if (!browseRelPath) return "";
  const parts = browseRelPath.split("/").filter(Boolean);
  parts.pop();
  return parts.join("/");
}

function onUploadFolderChange() {
  clearFileSummary();
  lastFileId = "";
  pendingFolderPcap = null;
  $("upload-folder-selected").textContent = "";
  const ul = $("upload-folder-list");
  ul.innerHTML = "";
  const input = $("upload-folder");
  const files = input.files ? Array.from(input.files) : [];
  const pcaps = files.filter((f) => /\.pcap$/i.test(f.name));
  pcaps.sort((a, b) =>
    (a.webkitRelativePath || a.name).localeCompare(
      b.webkitRelativePath || b.name,
      undefined,
      { sensitivity: "base" },
    ),
  );
  if (pcaps.length === 0) {
    const li = document.createElement("li");
    li.textContent =
      files.length === 0
        ? "No se ha elegido carpeta o está vacía."
        : "No hay ficheros .pcap en esa carpeta (ni en subcarpetas).";
    ul.appendChild(li);
    return;
  }
  for (const file of pcaps) {
    const li = document.createElement("li");
    const span = document.createElement("span");
    span.className = "name";
    span.textContent = file.webkitRelativePath || file.name;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "secondary";
    btn.textContent = "Usar";
    btn.addEventListener("click", () => {
      pendingFolderPcap = file;
      $("upload-folder-selected").textContent = `Seleccionado: ${file.webkitRelativePath || file.name}`;
      lastFileId = "";
      $("upload-status").textContent = "";
      summaryContext = { kind: "local", file };
      void fetchSummaryLocal(file);
    });
    li.appendChild(span);
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

async function doUpload() {
  let file = null;
  if (getUploadSource() === "folder") {
    file = pendingFolderPcap;
    if (!file) {
      $("upload-status").textContent = "Elige carpeta y pulsa Usar en un .pcap";
      return;
    }
  } else {
    const input = $("upload-file");
    if (!input.files || !input.files[0]) {
      $("upload-status").textContent = "Selecciona un .pcap";
      return;
    }
    file = input.files[0];
  }
  const fd = new FormData();
  fd.append("file", file, file.name);
  $("upload-btn").disabled = true;
  $("upload-status").textContent = "Subiendo…";
  showError("");
  try {
    const res = await fetch("/api/upload", { method: "POST", body: fd });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      $("upload-status").textContent = "";
      showError(data.detail || "Error al subir");
      return;
    }
    lastFileId = data.file_id;
    $("upload-status").textContent = `Listo. file_id: ${lastFileId}`;
    summaryContext = {
      kind: "json",
      body: {
        mode: "upload",
        file_id: lastFileId,
        browse_relative_path: "",
        absolute_path: "",
      },
    };
    await fetchSummaryJson(summaryContext.body);
  } finally {
    $("upload-btn").disabled = false;
  }
}

async function doPreview() {
  showError("");
  const img = $("preview-img");
  img.classList.add("hidden");
  img.removeAttribute("src");

  const mode = $("mode").value;
  const packet_range = $("packet-range").value.trim();

  const body = {
    mode,
    browse_relative_path: "",
    file_id: "",
    absolute_path: "",
    packet_range,
  };

  if (mode === "browse") {
    body.browse_relative_path = $("browse-relative-path").value.trim();
    if (!body.browse_relative_path) {
      showError("Elige un .pcap en el explorador.");
      return;
    }
  } else if (mode === "upload") {
    body.file_id = lastFileId;
    if (!body.file_id) {
      showError("Sube primero un .pcap.");
      return;
    }
  } else {
    body.absolute_path = $("absolute-path").value.trim();
    if (!body.absolute_path) {
      showError("Indica la ruta absoluta del .pcap.");
      return;
    }
  }

  $("preview-btn").disabled = true;
  try {
    const res = await fetch("/api/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      const detail = data.detail;
      const msg =
        typeof detail === "string"
          ? detail
          : Array.isArray(detail)
            ? detail.map((d) => d.msg || d).join("; ")
            : res.statusText;
      showError(msg || "Error al generar la vista previa");
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    img.src = url;
    img.classList.remove("hidden");
  } finally {
    $("preview-btn").disabled = false;
  }
}

$("mode").addEventListener("change", setModePanels);
$("browse-up").addEventListener("click", () => loadBrowse(parentBrowsePath()));
$("browse-refresh").addEventListener("click", () => loadBrowse(browseRelPath));

document.querySelectorAll('input[name="upload-source"]').forEach((el) => {
  el.addEventListener("change", () => {
    syncUploadSubpanels();
    lastFileId = "";
    $("upload-status").textContent = "";
    clearFileSummary();
    if (getUploadSource() === "folder") {
      resetSingleFileUploadUi();
    } else {
      resetFolderUploadUi();
    }
    const uf = $("upload-file");
    if (getUploadSource() === "file" && uf.files && uf.files[0]) {
      summaryContext = { kind: "local", file: uf.files[0] };
      void fetchSummaryLocal(uf.files[0]);
    }
  });
});

$("upload-file").addEventListener("change", () => {
  lastFileId = "";
  $("upload-status").textContent = "";
  const input = $("upload-file");
  const f = input.files && input.files[0];
  if (f && getUploadSource() === "file") {
    summaryContext = { kind: "local", file: f };
    void fetchSummaryLocal(f);
  } else {
    clearFileSummary();
  }
});

$("upload-folder").addEventListener("change", onUploadFolderChange);

$("upload-btn").addEventListener("click", doUpload);
$("preview-btn").addEventListener("click", doPreview);

$("absolute-path").addEventListener("input", scheduleAbsoluteSummary);
$("absolute-path").addEventListener("blur", () => {
  void tryAbsoluteSummary();
});

setModePanels();
syncUploadSubpanels();
loadBrowse("");

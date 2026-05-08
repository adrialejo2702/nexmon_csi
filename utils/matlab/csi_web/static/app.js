/* global fetch, URLSearchParams */

const $ = (id) => document.getElementById(id);

let browseRelPath = "";
let lastFileId = "";
/** @type {File | null} PCAP elegido desde una carpeta local (modo subir carpeta) */
let pendingFolderPcap = null;
let previewPythonPollTimer = null;
let currentLabels = [];
let selectedSummary = null;
/** @type {{ path: string, selected: boolean }[]} */
let selectedBrowsePcaps = [];
let browseSearchTerm = "";
let currentBrowseData = null;

/** @type {{ kind: "json", body: object } | { kind: "local", file: File } | null} */
let summaryContext = null;

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
  selectedSummary = null;
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
  const coresText =
    data.cores_detected != null ? Number(data.cores_detected).toLocaleString() : "—";

  const durTitle = data.duration_note ? escapeHtmlAttr(data.duration_note) : "";
  const rgbCount = Number(data.export_rgb_count || 0);
  const combinedCount = Number(data.export_combined_count || 0);
  let exportText = "No";
  if (rgbCount > 0 || combinedCount > 0) {
    const parts = [];
    if (rgbCount > 0) parts.push(`${rgbCount.toLocaleString()} RGB`);
    if (combinedCount > 0) parts.push(`${combinedCount.toLocaleString()} Combined`);
    exportText = `Sí (${parts.join(" + ")})`;
  }

  content.innerHTML = `<dl class="file-summary__dl">
      <dt>Fichero</dt><dd>${escapeHtml(data.file_name)}</dd>
      <dt>Paquetes CSI capturados</dt><dd>${Number(data.csi_packets_valid).toLocaleString()}</dd>
      <dt>Duración captura</dt><dd${durTitle ? ` title="${durTitle}"` : ""}>${durText}</dd>
      <dt>Cores detectados</dt><dd>${coresText}</dd>
      <dt>Paquetes/s</dt><dd>${rateText}</dd>
      <dt>Imágenes exportadas</dt><dd>${exportText}</dd>
    </dl>`;

  // Aviso de etiqueta automática por nombre de fichero.
  const noticeEl = $("auto-label-notice");
  if (noticeEl) {
    const detectedLabel = detectLabelFromFilename(data.file_name || "");
    if (detectedLabel) {
      noticeEl.textContent = `✓ Etiqueta automática detectada: "${detectedLabel}" (se asignará a todas las imágenes exportadas de este fichero)`;
      noticeEl.style.display = "";
    } else {
      noticeEl.textContent = "";
      noticeEl.style.display = "none";
    }
  }
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
      selectedSummary = null;
      return;
    }
    selectedSummary = data;
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
      selectedSummary = null;
      return;
    }
    selectedSummary = data;
    renderSummaryData(data);
  } catch (e) {
    renderSummaryError(e instanceof Error ? e.message : "Error de red");
  }
}

function showError(msg) {
  const el = $("error-msg");
  el.textContent = msg || "";
  el.classList.toggle("hidden", !msg);
}

function showWarning(msg) {
  const el = $("warning-msg");
  if (!el) return;
  el.textContent = msg || "";
  el.classList.toggle("hidden", !msg);
}

function setPreviewStatus(msg) {
  void msg;
}

function basenameFromPath(p) {
  return String(p || "")
    .split("/")
    .filter(Boolean)
    .pop() || "";
}

function resolveSelectedPcapName(body) {
  if (selectedSummary && selectedSummary.file_name) {
    return String(selectedSummary.file_name);
  }
  if (!body) return "";
  if (body.mode === "browse") {
    return basenameFromPath(body.browse_relative_path || "");
  }
  if (pendingFolderPcap && pendingFolderPcap.name) {
    return pendingFolderPcap.name;
  }
  return "";
}

function setPreviewFileName(text) {
  const el = $("preview-file-name");
  if (!el) return;
  el.textContent = text || "";
}

function renderBrowseSelectedList() {
  const ul = $("browse-selected-list");
  if (!ul) return;
  ul.innerHTML = "";
  if (selectedBrowsePcaps.length === 0) {
    const li = document.createElement("li");
    li.textContent = "Sin ficheros en la lista.";
    ul.appendChild(li);
    return;
  }
  for (const item of selectedBrowsePcaps) {
    const li = document.createElement("li");
    const left = document.createElement("label");
    left.className = "inline-label";
    const chk = document.createElement("input");
    chk.type = "checkbox";
    chk.checked = Boolean(item.selected);
    chk.addEventListener("change", () => {
      item.selected = chk.checked;
      updateActionButtons();
    });
    const txt = document.createElement("span");
    txt.textContent = item.path;
    left.appendChild(chk);
    left.appendChild(txt);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "secondary";
    btn.textContent = "Quitar";
    btn.addEventListener("click", () => {
      selectedBrowsePcaps = selectedBrowsePcaps.filter((p) => p.path !== item.path);
      renderBrowseSelectedList();
      updateActionButtons();
    });
    li.appendChild(left);
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

function addBrowseSelection(rel) {
  const existing = selectedBrowsePcaps.find((it) => it.path === rel);
  if (existing) {
    existing.selected = true;
  } else {
    selectedBrowsePcaps.push({ path: rel, selected: true });
  }
  renderBrowseSelectedList();
}

function syncBrowseRelativeSelectionAfterListChanges() {
  const input = $("browse-relative-path");
  if (!input) return;
  const current = String(input.value || "").trim();
  if (!current) return;
  const exists = selectedBrowsePcaps.some((it) => it.path === current);
  if (!exists) {
    input.value = "";
    setPreviewFileName("");
  }
}

function removeSelectedBrowseItems() {
  selectedBrowsePcaps = selectedBrowsePcaps.filter((it) => !it.selected);
  renderBrowseSelectedList();
  syncBrowseRelativeSelectionAfterListChanges();
  updateActionButtons();
}

function clearAllBrowseItems() {
  selectedBrowsePcaps = [];
  renderBrowseSelectedList();
  const input = $("browse-relative-path");
  if (input) input.value = "";
  setPreviewFileName("");
  updateActionButtons();
}

function listFilteredBrowsePcaps() {
  if (!currentBrowseData || !Array.isArray(currentBrowseData.pcaps)) return [];
  return currentBrowseData.pcaps.map((f) => (browseRelPath ? `${browseRelPath}/${f}` : f));
}

function useAllFilteredPcaps() {
  const rels = listFilteredBrowsePcaps();
  if (!rels.length) return;
  for (const rel of rels) {
    addBrowseSelection(rel);
  }
  const lastRel = rels[rels.length - 1];
  $("browse-relative-path").value = lastRel;
  summaryContext = {
    kind: "json",
    body: {
      mode: "browse",
      browse_relative_path: lastRel,
      file_id: "",
    },
  };
  void fetchSummaryJson(summaryContext.body);
  void loadLabelsForSelectedFile();
  updateActionButtons();
}

function detectLabelFromFilename(name) {
  const stem = name.toLowerCase().replace(/\.[^.]+$/, "");
  for (const label of ["movimiento", "vacio"]) {
    if (stem.includes(label)) return label;
  }
  return null;
}

function stopPreviewPythonPolling() {
  if (previewPythonPollTimer) {
    clearInterval(previewPythonPollTimer);
    previewPythonPollTimer = null;
  }
}

function startPreviewPythonPolling() {
  stopPreviewPythonPolling();
  previewPythonPollTimer = setInterval(async () => {
    try {
      const res = await fetch("/api/preview-python-status");
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return;
      if (!data.running) {
        stopPreviewPythonPolling();
      }
    } catch {
      // Si falla puntualmente, mantenemos el último estado visible.
    }
  }, 1200);
}

function clearExportStatus() {
  const status = $("export-status");
  if (status) status.textContent = "";
}

function setExportProgress(percent, text, isError = false) {
  const wrap = $("export-progress");
  const fill = $("export-progress-fill");
  const label = $("export-progress-text");
  if (!wrap || !fill || !label) return;
  wrap.classList.remove("hidden");
  fill.style.width = `${Math.max(0, Math.min(100, percent))}%`;
  fill.style.backgroundColor = isError ? "#c62828" : "";
  label.textContent = text || "";
}

function resetExportProgress() {
  const wrap = $("export-progress");
  const fill = $("export-progress-fill");
  const label = $("export-progress-text");
  if (!wrap) return;
  wrap.classList.add("hidden");
  if (fill) {
    fill.style.width = "0%";
    fill.style.backgroundColor = "";
  }
  if (label) label.textContent = "";
}

function setLabelsStatus(msg) {
  const el = $("labels-status");
  if (!el) return;
  el.textContent = msg || "";
}

function hasAnyExportFormatSelected() {
  return true; // Exportación fija en RGB.
}

function hasSelectedFile() {
  try {
    if ($("mode").value === "browse") {
      selectedPreviewBodies();
    } else {
      selectedFileBody();
    }
    return true;
  } catch {
    return false;
  }
}

function getPreviewModes() {
  const regular = Boolean($("preview-regular")?.checked);
  const combined = Boolean($("preview-combined")?.checked);
  const modes = [];
  if (regular) modes.push(false);
  if (combined) modes.push(true);
  return modes;
}

function getSavePreviewModes() {
  const normal = Boolean($("save-preview-normal")?.checked);
  const combined = Boolean($("save-preview-combined")?.checked);
  const modes = [];
  if (normal) modes.push(false);
  if (combined) modes.push(true);
  return modes;
}

function hasValidSecondsIntervalInput() {
  const startRaw = $("label-start-sec").value.trim();
  const endRaw = $("label-end-sec").value.trim();
  if (!startRaw && !endRaw) return true; // Vacío => etiquetar todo el archivo.
  if (!startRaw || !endRaw) return false;
  const startSec = Number.parseFloat(startRaw);
  const endSec = Number.parseFloat(endRaw);
  return Number.isFinite(startSec) && startSec >= 0 && Number.isFinite(endSec) && endSec >= startSec;
}

function updateActionButtons() {
  const hasFile = hasSelectedFile();
  const hasFormats = hasAnyExportFormatSelected();
  $("preview-btn").disabled = !hasFile || getPreviewModes().length === 0;
  $("save-preview-images-btn").disabled = !hasFile || getSavePreviewModes().length === 0;
  $("export-btn").disabled = !(hasFile && hasFormats);
  $("add-label-btn").disabled = !(hasFile && selectedSummary && hasValidSecondsIntervalInput());
  $("save-labels-btn").disabled = !(hasFile && currentLabels.length > 0);
}

function updateExportButtonState() {
  updateActionButtons();
}

function selectedFileBody() {
  const mode = $("mode").value;
  const body = {
    mode,
    browse_relative_path: "",
    file_id: "",
  };
  if (mode === "browse") {
    body.browse_relative_path = $("browse-relative-path").value.trim();
    if (!body.browse_relative_path) {
      throw new Error("Elige un .pcap en el explorador.");
    }
  } else {
    body.file_id = lastFileId;
    if (!body.file_id) {
      throw new Error("Sube primero un .pcap.");
    }
  }
  return body;
}

function selectedPreviewBodies() {
  const mode = $("mode").value;
  if (mode !== "browse") {
    return [selectedFileBody()];
  }
  const rels = selectedBrowsePcaps.filter((it) => it.selected).map((it) => it.path);
  if (!rels.length) {
    throw new Error("Marca al menos un .pcap en la lista de representaciones.");
  }
  return rels.map((rel) => ({
    mode: "browse",
    browse_relative_path: rel,
    file_id: "",
  }));
}

function normalizeLabelsForRender(labels) {
  return labels
    .filter((it) => it && Number(it.start_packet) >= 1 && Number(it.end_packet) >= Number(it.start_packet))
    .map((it) => ({
      label: String(it.label || ""),
      start_packet: Number(it.start_packet),
      end_packet: Number(it.end_packet),
      core: String(it.core || "all"),
    }))
    .sort((a, b) => a.start_packet - b.start_packet);
}

function renderLabelsList() {
  const ul = $("labels-list");
  ul.innerHTML = "";
  if (!currentLabels.length) {
    const li = document.createElement("li");
    li.textContent = "Sin etiquetas.";
    ul.appendChild(li);
    return;
  }
  currentLabels.forEach((it, idx) => {
    const li = document.createElement("li");
    const span = document.createElement("span");
    span.className = "name";
    const coreText = it.core === "all" ? "Todos" : `Core ${it.core}`;
    span.textContent = `[${coreText}] ${it.start_packet}-${it.end_packet} -> ${it.label}`;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "secondary";
    btn.textContent = "Quitar";
    btn.addEventListener("click", () => {
      currentLabels.splice(idx, 1);
      renderLabelsList();
      setLabelsStatus("");
    });
    li.appendChild(span);
    li.appendChild(btn);
    ul.appendChild(li);
  });
}

function clearLabelsUi() {
  currentLabels = [];
  renderLabelsList();
  setLabelsStatus("");
  updateActionButtons();
}

async function loadLabelsForSelectedFile() {
  let body;
  try {
    body = selectedFileBody();
  } catch {
    clearLabelsUi();
    return;
  }
  try {
    const res = await fetch("/api/labels/load", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      clearLabelsUi();
      return;
    }
    currentLabels = normalizeLabelsForRender(Array.isArray(data.labels) ? data.labels : []);
    renderLabelsList();
    updateActionButtons();
  } catch {
    clearLabelsUi();
  }
}

function addLabelFromInputs() {
  const startRaw = $("label-start-sec").value.trim();
  const endRaw = $("label-end-sec").value.trim();
  const fullFile = !startRaw && !endRaw;
  const startSec = Number.parseFloat(startRaw);
  const endSec = Number.parseFloat(endRaw);
  const label = $("label-name").value;
  const core = $("label-core").value;
  if (!selectedSummary) {
    showError("Primero selecciona un fichero para calcular la equivalencia segundos->paquetes.");
    return;
  }
  const duration = Number(selectedSummary.duration_seconds || 0);
  const totalPkts = Number(selectedSummary.csi_packets_valid || 0);
  if (!(duration > 0) || !(totalPkts > 0)) {
    showError("No se pudo obtener duración/paquetes del fichero para convertir segundos.");
    return;
  }
  if (!label) {
    showError("Selecciona una etiqueta.");
    return;
  }
  let start = 1;
  let end = totalPkts;
  if (!fullFile) {
    if (!startRaw || !endRaw) {
      showError("Si introduces intervalo, rellena inicio y fin.");
      return;
    }
    if (!Number.isFinite(startSec) || startSec < 0 || !Number.isFinite(endSec) || endSec < startSec) {
      showError("Intervalo inválido: usa inicio/fin en segundos con fin >= inicio.");
      return;
    }
    const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
    const s0 = clamp(startSec, 0, duration);
    const s1 = clamp(endSec, 0, duration);
    start = clamp(Math.floor((s0 / duration) * totalPkts) + 1, 1, totalPkts);
    end = clamp(Math.ceil((s1 / duration) * totalPkts), start, totalPkts);
  }
  showError("");
  currentLabels.push({
    start_packet: start,
    end_packet: end,
    label,
    core,
  });
  currentLabels = normalizeLabelsForRender(currentLabels);
  renderLabelsList();
  const coreTxt = core === "all" ? "Todos" : `Core ${core}`;
  const intervalTxt = fullFile ? "todo el archivo" : `paquetes: ${start}-${end}`;
  setLabelsStatus(`Etiqueta añadida en ${intervalTxt}, ${coreTxt} (pendiente de guardar).`);
  updateActionButtons();
}

async function saveLabels() {
  let body;
  try {
    body = selectedFileBody();
  } catch (e) {
    showError(e instanceof Error ? e.message : "Selecciona un fichero para guardar etiquetas.");
    return false;
  }
  try {
    const res = await fetch("/api/labels/save", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...body,
        labels: currentLabels.map((it) => ({
          label: it.label,
          start_packet: it.start_packet,
          end_packet: it.end_packet,
          core: it.core || "all",
        })),
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = data.detail;
      const msg = typeof detail === "string" ? detail : res.statusText;
      showError(msg || "Error guardando etiquetas.");
      return false;
    }
    showError("");
    setLabelsStatus(`Etiquetas guardadas: ${data.saved}.`);
    let generatedMsg = "";
    if (Boolean($("generate-impulse-labeled-images").checked)) {
      const payload = {
        ...body,
        generate_rgb: true,
        generate_gray: false,
        no_overlap: Boolean($("export-no-overlap").checked),
        regenerate_existing: Boolean($("export-regenerate-existing").checked),
        export_with_label_name: true,
        combined: Boolean($("preview-combined")?.checked),
      };
      const res2 = await fetch("/api/export-windows", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data2 = await res2.json().catch(() => ({}));
      if (!res2.ok) {
        const detail2 = data2.detail;
        const msg2 = typeof detail2 === "string" ? detail2 : res2.statusText;
        showError(msg2 || "Error generando imágenes con etiquetas Edge Impulse.");
        return false;
      }
      if (data2.status === "skipped_existing") {
        generatedMsg = " Imágenes ya existentes (activa Regenerar para sobrescribir).";
      } else {
        generatedMsg = ` Imágenes Edge Impulse generadas: ${data2.labeled_windows_generated}.`;
      }
    }
    setLabelsStatus(`Etiquetas guardadas: ${data.saved}.${generatedMsg}`);
    updateActionButtons();
    return true;
  } catch (e) {
    showError(e instanceof Error ? e.message : "Error de red guardando etiquetas.");
    return false;
  }
}

function syncUploadSubpanels() {
  // Modo upload simplificado: solo carpeta local.
  $("upload-folder-wrap").classList.remove("hidden");
}

function resetFolderUploadUi() {
  pendingFolderPcap = null;
  $("upload-folder").value = "";
  $("upload-folder-list").innerHTML = "";
  $("upload-folder-selected").textContent = "";
}

function resetSingleFileUploadUi() {
  // Ya no se usa input de archivo único.
}

function setModePanels() {
  const mode = $("mode").value;
  clearFileSummary();
  clearExportStatus();
  resetExportProgress();
  setPreviewFileName("");
  showWarning("");
  clearLabelsUi();
  $("browse-panel").classList.toggle("hidden", mode !== "browse");
  $("upload-panel").classList.toggle("hidden", mode !== "upload");
  if (mode === "upload") {
    syncUploadSubpanels();
  }
}

async function loadBrowse(path) {
  showError("");
  showWarning("");
  const params = new URLSearchParams();
  if (path) params.set("path", path);
  const search = browseSearchTerm.trim();
  if (search) params.set("search", search);
  const q = params.toString() ? `?${params.toString()}` : "";
  const res = await fetch(`/api/browse${q}`);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    showError(data.detail || res.statusText || "Error al listar");
    return;
  }
  currentBrowseData = data;
  browseRelPath = currentBrowseData.path || "";
  $("browse-path").textContent = browseRelPath || "(raíz)";
  renderBrowseList();
}

function renderBrowseList() {
  const ul = $("browse-list");
  if (!ul || !currentBrowseData) return;
  ul.innerHTML = "";
  const dateDirPattern = /^2026\d{4}$/;
  const visibleDirectories = (currentBrowseData.directories || []).filter((d) =>
    dateDirPattern.test(String(d)),
  );

  for (const d of visibleDirectories) {
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

  const visiblePcaps = currentBrowseData.pcaps || [];
  for (const f of visiblePcaps) {
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
      addBrowseSelection(rel);
      summaryContext = {
        kind: "json",
        body: {
          mode: "browse",
          browse_relative_path: rel,
          file_id: "",
        },
      };
      void fetchSummaryJson(summaryContext.body);
      void loadLabelsForSelectedFile();
    });
    li.appendChild(span);
    li.appendChild(btn);
    ul.appendChild(li);
  }

  if (browseSearchTerm.trim() && visiblePcaps.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No se encontraron archivos .pcap con ese texto.";
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
  clearExportStatus();
  resetExportProgress();
  setPreviewFileName("");
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
      clearLabelsUi();
    });
    li.appendChild(span);
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

async function doUpload() {
  const file = pendingFolderPcap;
  if (!file) {
    $("upload-status").textContent = "Elige carpeta y pulsa Usar en un .pcap";
    return;
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
      },
    };
    await fetchSummaryJson(summaryContext.body);
    await loadLabelsForSelectedFile();
  } finally {
    $("upload-btn").disabled = false;
  }
}

async function doPreview() {
  showError("");
  showWarning("");
  const packet_range = "";
  let bodies;
  try {
    const modes = getPreviewModes();
    if (!modes.length) {
      throw new Error("Marca al menos una opción de vista previa (Regular o Combined).");
    }
    bodies = [];
    for (const base of selectedPreviewBodies()) {
      for (const combined of modes) {
        bodies.push({
          ...base,
          packet_range,
          combined,
        });
      }
    }
    if (bodies.length === 1) {
      const pcapName = resolveSelectedPcapName(bodies[0]);
      setPreviewFileName(pcapName ? `PCAP representado: ${pcapName}` : "");
    } else {
      setPreviewFileName(`Vistas a representar: ${bodies.length}`);
    }
  } catch (e) {
    showError(e instanceof Error ? e.message : "Falta seleccionar fichero");
    return;
  }

  $("preview-btn").disabled = true;
  try {
    const warnings = [];
    const errors = [];
    for (const body of bodies) {
      const res = await fetch("/api/preview-python", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
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
        if (res.status === 409) {
          warnings.push(msg || `Vista ya abierta: ${body.browse_relative_path || "archivo"}`);
          continue;
        }
        errors.push(msg || `Error en ${body.browse_relative_path || "archivo"}`);
        continue;
      }
    }
    if (warnings.length) {
      showWarning(warnings.join(" | "));
    }
    if (errors.length) {
      showError(errors.join(" | "));
    } else {
      startPreviewPythonPolling();
    }
  } finally {
    $("preview-btn").disabled = false;
  }
}

async function doSavePreviewImages() {
  showError("");
  showWarning("");
  const packet_range = "";
  let baseBodies;
  try {
    baseBodies = selectedPreviewBodies();
  } catch (e) {
    showError(e instanceof Error ? e.message : "Falta seleccionar fichero");
    return;
  }
  const modes = getSavePreviewModes();
  if (!modes.length) {
    showError("Marca al menos una opción para guardar (normal o combinada).");
    return;
  }

  const bodies = [];
  for (const base of baseBodies) {
    for (const combined of modes) {
      bodies.push({
        ...base,
        packet_range,
        combined,
      });
    }
  }

  $("save-preview-images-btn").disabled = true;
  try {
    const errors = [];
    let savedCount = 0;
    const total = bodies.length;
    for (let idx = 0; idx < bodies.length; idx++) {
      const body = bodies[idx];
      showWarning(`Exportando ${idx + 1}/${total}...`);
      const saveRes = await fetch("/api/preview-save-image", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const saveData = await saveRes.json().catch(() => ({}));
      if (!saveRes.ok) {
        const saveDetail = saveData.detail;
        const saveMsg =
          typeof saveDetail === "string"
            ? saveDetail
            : Array.isArray(saveDetail)
              ? saveDetail.map((d) => d.msg || d).join("; ")
              : saveRes.statusText;
        errors.push(saveMsg || `Error guardando PNG en ${body.browse_relative_path || "archivo"}`);
        continue;
      }
      if (saveData.status === "ok") savedCount += 1;
    }
    if (savedCount > 0 || total > 0) {
      const failed = Math.max(0, total - savedCount);
      showWarning(
        failed > 0
          ? `Completado: ${savedCount}/${total} (${failed} con error).`
          : `Exportación completada: ${savedCount}/${total}.`
      );
    }
    if (errors.length) {
      showError(errors.join(" | "));
    }
  } finally {
    updateActionButtons();
  }
}

function _selectedExportBodies() {
  const mode = $("mode").value;
  if (mode === "browse") {
    const rels = selectedBrowsePcaps.filter((it) => it.selected).map((it) => it.path);
    if (rels.length > 0) {
      return rels.map((rel) => ({ mode: "browse", browse_relative_path: rel, file_id: "" }));
    }
  }
  // Fallback: fichero único activo (modo upload o browse sin lista marcada).
  return [selectedFileBody()];
}

async function doExportWindows() {
  showError("");
  const status = $("export-status");
  if (status) status.classList.add("hidden");

  let bodies;
  try {
    bodies = _selectedExportBodies();
  } catch (e) {
    showError(e instanceof Error ? e.message : "Falta seleccionar fichero");
    setExportProgress(100, "Error", true);
    return;
  }

  const sharedOpts = {
    generate_rgb: true,
    generate_gray: false,
    no_overlap: Boolean($("export-no-overlap").checked),
    regenerate_existing: Boolean($("export-regenerate-existing").checked),
    export_with_label_name: Boolean($("generate-impulse-labeled-images").checked),
    combined: Boolean($("preview-combined")?.checked),
  };

  $("export-btn").disabled = true;
  if (status) status.textContent = "";

  const results = [];
  const errors = [];

  try {
    for (let i = 0; i < bodies.length; i++) {
      const body = bodies[i];
      const label = body.browse_relative_path
        ? body.browse_relative_path.split("/").pop()
        : `fichero ${i + 1}`;
      const total = bodies.length;
      setExportProgress(Math.round(10 + (80 * i) / total), `Exportando ${i + 1}/${total}: ${label}...`);

      const payload = { ...body, ...sharedOpts };
      const res = await fetch("/api/export-windows", {
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
        errors.push(`${label}: ${msg || "Error exportando"}`);
        continue;
      }

      if (data.status === "skipped_existing") {
        errors.push(`${label}: ya existen imágenes (activa "Regenerar" para sobrescribir)`);
        continue;
      }

      results.push({ label, data, payload });
    }
  } finally {
    updateExportButtonState();
  }

  if (errors.length > 0 && results.length === 0) {
    showError(errors.join("\n"));
    setExportProgress(100, "Error", true);
    return;
  }

  // Construir mensaje de resumen.
  const lines = results.map(({ label, data, payload }) => {
    const modeTxt = payload.combined ? " combinado" : "";
    const labeledMode = Boolean(payload.export_with_label_name);
    const exportedCount = labeledMode
      ? Number(data.labeled_windows_generated ?? data.windows_generated ?? 0)
      : Number(data.windows_generated ?? 0);
    const autoLabelTxt = data.auto_label ? ` [${data.auto_label}]` : "";
    const skippedTxt =
      labeledMode && Number(data.unlabeled_windows_skipped || 0) > 0
        ? ` (descartadas sin etiqueta: ${Number(data.unlabeled_windows_skipped)})`
        : "";
    const prefix = bodies.length > 1 ? `${label}: ` : "";
    return `${prefix}${exportedCount} imágenes RGB${modeTxt}${autoLabelTxt}${skippedTxt}`;
  });

  if (errors.length > 0) {
    lines.push(...errors.map((e) => `⚠ ${e}`));
  }

  if (status) {
    status.textContent = lines.join(" | ");
    status.classList.remove("hidden");
  }
  const total = bodies.length;
  const okCount = results.length;
  const failed = Math.max(0, total - okCount);
  setExportProgress(
    100,
    failed > 0 ? `Completado: ${okCount}/${total} (${failed} con error).` : `Exportación completada: ${okCount}/${total}.`
  );
}

$("mode").addEventListener("change", setModePanels);
$("browse-up").addEventListener("click", () => loadBrowse(parentBrowsePath()));
$("browse-refresh").addEventListener("click", () => loadBrowse(browseRelPath));
$("browse-search").addEventListener("input", (ev) => {
  browseSearchTerm = String(ev.target?.value || "");
  void loadBrowse(browseRelPath);
});
$("browse-search-clear").addEventListener("click", () => {
  browseSearchTerm = "";
  $("browse-search").value = "";
  void loadBrowse(browseRelPath);
});
$("browse-use-all-filtered").addEventListener("click", () => {
  useAllFilteredPcaps();
});
$("browse-remove-selected").addEventListener("click", removeSelectedBrowseItems);
$("browse-clear-all").addEventListener("click", clearAllBrowseItems);

$("upload-folder").addEventListener("change", onUploadFolderChange);

$("upload-btn").addEventListener("click", doUpload);
$("preview-btn").addEventListener("click", doPreview);
$("save-preview-images-btn").addEventListener("click", doSavePreviewImages);
$("export-btn").addEventListener("click", doExportWindows);
$("add-label-btn").addEventListener("click", addLabelFromInputs);
$("save-labels-btn").addEventListener("click", () => {
  void saveLabels();
});
["label-start-sec", "label-end-sec", "label-name", "label-core"].forEach((id) => {
  $(id).addEventListener("input", updateActionButtons);
  $(id).addEventListener("change", updateActionButtons);
});
[
  "browse-relative-path",
  "generate-impulse-labeled-images",
  "preview-regular",
  "preview-combined",
  "save-preview-normal",
  "save-preview-combined",
].forEach((id) => {
  $(id).addEventListener("change", updateActionButtons);
});

setModePanels();
syncUploadSubpanels();
updateExportButtonState();
renderLabelsList();
renderBrowseSelectedList();
loadBrowse("");

/**
 * Resume Tailor — Frontend Application
 *
 * All application state lives in a single plain object that is persisted to
 * localStorage after every change. The render cycle is always: state → DOM.
 * Nothing mutates the DOM directly; every change goes through state first.
 *
 * Architecture:
 *   init()         — bootstrap: load state → load API config  render
 *   bindStaticEvents() — wire up every button/input that doesn't depend on state
 *   renderAll()    — redraw editors + preview + score ring + feedback list
 *   runAi(mode)    — POST to /api/ai, update state from response
 *   handleFileLoad — dispatch PDF/DOCX/TXT to the right /api/parse-resume path
 */

// localStorage key — increment the version suffix if the state schema changes
// so old saved data doesn't cause a crash on upgrade.
const STORAGE_KEY = "local-resume-tailor:v2";

// Blank / default state
// This is the canonical shape of the application state. Every key must be here
// so the merge() deep-merge function has a baseline to fill missing fields into.
const blankState = () => ({
  title: "Untitled Resume",
  sectionOrder: ["summary", "skills", "experience", "education", "projects", "certifications"],
  jobDescription: "",
  design: { showLinks: true },
  resume: {
    contact: { name: "", email: "", phone: "", location: "", linkedin: "", github: "", website: "" },
    summary: "",
    skills: [],
    experience: [],
    education: [],
    projects: [],
    certifications: [],
    customSections: [],   // sections like Volunteering, Awards, Publications, etc.
  },
  analysis: null,
  selectedFeedback: [],  // indices of feedback items the user has ticked
});

// Common filler words to ignore when scoring keyword coverage
const stopWords = new Set(
  "and the for with from into your you are will this that have has must should our their they them about using use role work team ability able across plus such based while within where when what all more most per via can not"
    .split(" ")
);

const defaultState = blankState();
let state = blankState();   // always start fresh — localStorage cleared in init()
let config = {};
let saveTimer = null;

// Track which editor sections are expanded (survives re-renders)
const openSections = new Set();

// Drag-and-drop state for section reordering
let _dragSrcKey = null;
let _dragFromHandle = false;

// Short alias for getElementById
const $ = (id) => document.getElementById(id);

// Notification helper
// Creates a small toast that auto-dismisses. Click to dismiss early.
function showToast(message, type = "info", duration = 5000) {
  const container = $("toastContainer");
  const icons = { success: "✓", error: "✕", warning: "⚠", info: "ℹ" };

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || icons.info}</span>
    <span class="toast-msg">${escapeHtml(message)}</span>
  `;
  container.appendChild(toast);

  const dismiss = () => {
    toast.classList.add("fade-out");
    toast.addEventListener("animationend", () => toast.remove(), { once: true });
  };
  const timer = setTimeout(dismiss, duration);
  toast.addEventListener("click", () => { clearTimeout(timer); dismiss(); });
}

// Bootstrap
init();

async function init() {
  // Wipe any data saved from a previous browser session so every page load
  // starts with a blank slate as required by the product spec.
  localStorage.removeItem(STORAGE_KEY);
  state = blankState();
  bindStaticEvents();
  await loadConfig();    // check if the backend has a Cerebras key wired up
  hydrateControls();     // push saved state back into form fields
  renderAll();           // first full render
}

// State persistence
// Load state from localStorage, deep-merging with the blank default so any new
// fields added to blankState() in future versions are automatically present.
function loadState() {
  try {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY));
    return merge(defaultState, stored || {});
  } catch {
    return structuredClone(defaultState);
  }
}

// Deep-merge: arrays are replaced wholesale (not concatenated); plain objects
// are merged key-by-key; primitives use the patch value or fall back to base.
function merge(base, patch) {
  if (Array.isArray(base)) return Array.isArray(patch) ? patch : structuredClone(base);
  if (!base || typeof base !== "object") return patch ?? base;
  const out = structuredClone(base);
  for (const [key, value] of Object.entries(patch || {})) {
    out[key] = key in out ? merge(out[key], value) : value;
  }
  return out;
}

// Debounce localStorage writes to 180 ms so rapid typing doesn't cause jank.
function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  }, 180);
}

// Config
// Ask the backend if the Cerebras key is present so we can show a warning if not.
async function loadConfig() {
  try {
    const res = await fetch("/api/config");
    config = await res.json();
  } catch {
    config = {};
  }
}

// Event bindings
// Wire up every control that exists in the initial HTML. Section-level bindings
// (editor fields, drag handles, etc.) are re-bound in bindSectionEditors()
// after each render because those elements are rebuilt by innerHTML.
function bindStaticEvents() {
  // Print-to-PDF
  $("downloadBtn").addEventListener("click", () => {
    document.title = safeFileName(state.resume.contact.name || "resume");
    window.print();
  });

  // AI actions
  $("aiTailorBtn").addEventListener("click", () => {
    if (!hasResume()) { showToast("Upload your resume first.", "warning"); return; }
    if (!state.jobDescription || state.jobDescription.trim().length < 30) {
      showToast("Paste a job description first.", "warning"); return;
    }
    runAi("tailor");
  });

  $("applyFeedbackBtn").addEventListener("click", () => {
    if (!state.selectedFeedback.length) {
      showToast("Tick at least one recommendation in the Analysis panel to apply.", "warning"); return;
    }
    runAi("improve");
  });

  $("clearFeedbackBtn").addEventListener("click", () => update({ analysis: null, selectedFeedback: [] }));

  // Editor add buttons
  $("addExperienceBtn").addEventListener("click", addExperience);
  $("addSectionBtn").addEventListener("click", addCustomSection);

  // File upload
  $("importFile").addEventListener("change", importFile);

  // Drag-and-drop on the drop zone
  const dz = $("dropZone");
  dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("drag-over"); });
  dz.addEventListener("dragleave", () => dz.classList.remove("drag-over"));
  dz.addEventListener("drop", (e) => {
    e.preventDefault();
    dz.classList.remove("drag-over");
    const file = e.dataTransfer.files?.[0];
    if (file) handleFileLoad(file);
  });

  // Collapsible panels
  $("uploadToggle").addEventListener("click", () => {
    $("uploadBody").classList.toggle("open");
    $("uploadChevron").classList.toggle("open");
  });

  $("jobPaneToggle").addEventListener("click", (e) => {
    if (e.target.tagName === "BUTTON" && e.target !== $("jobPaneToggle")) return;
    $("jobPaneBody").classList.toggle("open");
    $("jobPaneChevron").classList.toggle("open");
  });

  $("analysisToggle").addEventListener("click", () => {
    $("analysisBody").classList.toggle("open");
  });

  $("editorToggle").addEventListener("click", () => {
    $("editorBody").classList.toggle("open");
    $("editorChevron").classList.toggle("open");
  });

  // Live binding: JD textarea → recompute job match on every keystroke
  bindInput("jobDescription", (v) => {
    state.jobDescription = v;
  });

  bindInput("showLinks", (v, e) => (state.design.showLinks = e.target.checked), "change");
}

// Push saved state values back into form controls after load or state reset.
function hydrateControls() {
  $("jobDescription").value = state.jobDescription;
  $("showLinks").checked = state.design.showLinks;
}

// Generic input binder. Calls setter on every change and triggers a render.
function bindInput(id, setter, eventName = "input") {
  $(id).addEventListener(eventName, (e) => {
    setter(e.target.type === "checkbox" ? e.target.checked : e.target.value, e);
    renderAll();
    persist();
  });
}

// Convenience: deep-merge a patch into state then re-render and persist.
function update(patch) {
  state = merge(state, patch);
  hydrateControls();
  renderAll();
  persist();
}


// Workflow helpers
// Returns true when the user has loaded meaningful resume content into state.
function hasResume() {
  const r = state.resume;
  return !!(
    r.contact.name ||
    r.summary ||
    (r.experience && r.experience.length) ||
    (r.skills && r.skills.length) ||
    (r.education && r.education.length)
  );
}

// Word count for any string (trims, splits on whitespace, ignores empty tokens).
function countWords(text) {
  return (text || "").trim().split(/\s+/).filter(Boolean).length;
}


// Button state management
function updateButtonStates() {
  const resumeReady = hasResume();
  const jdReady = !!(state.jobDescription && state.jobDescription.trim().length >= 30);

  const tailorBtn = $("aiTailorBtn");
  if (tailorBtn && !tailorBtn._busyLocked) {
    tailorBtn.disabled = !resumeReady || !jdReady;
  }

  const applyBtn = $("applyFeedbackBtn");
  if (applyBtn && !applyBtn._busyLocked) {
    applyBtn.disabled = !(state.selectedFeedback && state.selectedFeedback.length > 0);
  }
}

// Render cycle
function renderAll() {
  renderEditors();
  renderPreview();
  renderJobMatch();
  renderFeedback();
  updateButtonStates();
}

// Editor panel
// Rebuilds the entire left-panel editor DOM from state. After rebuilding,
// re-attaches all the event listeners that live on those elements.
function renderEditors() {
  // Populate the static contact fields
  const c = state.resume.contact;
  setValue("nameInput", c.name);
  setValue("emailInput", c.email);
  setValue("phoneInput", c.phone);
  setValue("locationInput", c.location);
  setValue("linkedinInput", c.linkedin);
  setValue("githubInput", c.github);
  setValue("websiteInput", c.website);

  // Wire up contact field live binding (once only — guard with dataset.bound)
  const contactMap = {
    nameInput: "name", emailInput: "email", phoneInput: "phone",
    locationInput: "location", linkedinInput: "linkedin",
    githubInput: "github", websiteInput: "website",
  };
  for (const [id, key] of Object.entries(contactMap)) {
    if (!$(id).dataset.bound) {
      $(id).dataset.bound = "true";
      $(id).addEventListener("input", (e) => {
        state.resume.contact[key] = e.target.value;
        renderPreview();
        persist();
      });
    }
  }

  // Ensure every custom section has its ID in sectionOrder (new ones land at the end)
  if (!state.sectionOrder) state.sectionOrder = [...defaultState.sectionOrder];
  for (const cs of (state.resume.customSections || [])) {
    if (!state.sectionOrder.includes(cs.id)) state.sectionOrder.push(cs.id);
  }

  // Built-in section renderers keyed by their sectionOrder identifier
  const builtIn = {
    summary: () => sectionTextarea("Professional Summary", "summary", state.resume.summary),
    skills: () => skillsEditor(),
    experience: () => repeatingEditor("Work Experience", "experience", state.resume.experience, experienceFields),
    education: () => repeatingEditor("Education", "education", state.resume.education, educationFields),
    projects: () => repeatingEditor("Projects", "projects", state.resume.projects, projectFields),
    certifications: () => repeatingEditor("Certifications", "certifications", state.resume.certifications, certificationFields),
  };

  const sections = state.sectionOrder
    .map(key => {
      if (builtIn[key]) return builtIn[key]();
      // Custom sections (Volunteering, Awards, etc.) are rendered generically
      const csIdx = (state.resume.customSections || []).findIndex(cs => cs.id === key);
      if (csIdx !== -1) return customSectionEditor(state.resume.customSections[csIdx], csIdx);
      return "";
    })
    .filter(Boolean);

  $("sectionList").innerHTML = sections.join("");
  bindSectionEditors();
}

// Only update a field's value when it is not currently focused (to avoid
// stomping on in-progress keystrokes during a rapid re-render).
function setValue(id, value) {
  const el = $(id);
  if (document.activeElement !== el) el.value = value || "";
}

// Section HTML builders
function sectionTextarea(title, key, value) {
  const open = openSections.has(key) ? "open" : "";
  return `
    <div class="editor-section ${open}" data-section="${key}" draggable="true">
      <div class="section-header">
        <button class="section-toggle" type="button">
          <span class="drag-handle" title="Drag to reorder">⠿</span>${title}<span>${open ? "v" : ">"}</span>
        </button>
        <button class="remove-section-btn" type="button" data-action="remove-section" data-key="${key}">Remove</button>
      </div>
      <div class="section-body">
        <label>${title}<textarea data-path="resume.${key}" rows="7">${escapeHtml(value || "")}</textarea></label>
      </div>
    </div>`;
}

function skillsEditor() {
  const open = openSections.has("skills") ? "open" : "";
  const rows = state.resume.skills.map((skill, i) => `
    <label>Skill Category<input data-path="resume.skills.${i}.label" value="${escapeAttr(skill.label)}"></label>
    <label>Skills<textarea data-path="resume.skills.${i}.items" rows="3">${escapeHtml(skill.items)}</textarea></label>
  `).join("");
  return `
    <div class="editor-section ${open}" data-section="skills" draggable="true">
      <div class="section-header">
        <button class="section-toggle" type="button">
          <span class="drag-handle" title="Drag to reorder">⠿</span>Key Skills<span>${open ? "v" : ">"}</span>
        </button>
        <button class="remove-section-btn" type="button" data-action="remove-section" data-key="skills">Remove</button>
      </div>
      <div class="section-body">
        ${rows}
        <div class="mini-actions"><button type="button" data-action="add-skill">Add Skill Group</button></div>
      </div>
    </div>`;
}

function repeatingEditor(title, key, items, fieldsFn) {
  const open = openSections.has(key) ? "open" : "";
  const rows = (items || []).map((item, i) => `
    <div class="repeat-card">
      ${fieldsFn(item, i, key)}
      <div class="mini-actions">
        <button type="button" data-action="add-bullet" data-key="${key}" data-index="${i}">Add Bullet</button>
        <button type="button" data-action="remove-item" data-key="${key}" data-index="${i}">Remove</button>
      </div>
    </div>
  `).join("") || `<div class="empty-state">No entries yet.</div>`;
  return `
    <div class="editor-section ${open}" data-section="${key}" draggable="true">
      <div class="section-header">
        <button class="section-toggle" type="button">
          <span class="drag-handle" title="Drag to reorder">⠿</span>${title}<span>${open ? "v" : ">"}</span>
        </button>
        <button class="remove-section-btn" type="button" data-action="remove-section" data-key="${key}">Remove</button>
      </div>
      <div class="section-body">
        ${rows}
        <div class="mini-actions">
          <button type="button" data-action="add-item" data-key="${key}">Add ${title}</button>
        </div>
      </div>
    </div>`;
}

function customSectionEditor(cs, csIdx) {
  const open = openSections.has(cs.id) ? "open" : "";
  const rows = (cs.items || []).map((item, i) => `
    <div class="repeat-card">
      ${inputField("Role / Title", `resume.customSections.${csIdx}.items.${i}.role`, item.role)}
      ${inputField("Organisation", `resume.customSections.${csIdx}.items.${i}.org`, item.org)}
      ${inputField("Location", `resume.customSections.${csIdx}.items.${i}.location`, item.location)}
      ${inputField("Dates", `resume.customSections.${csIdx}.items.${i}.dates`, item.dates)}
      ${(item.bullets || []).map((b, bi) => `
        <label>Bullet ${bi + 1}<textarea data-path="resume.customSections.${csIdx}.items.${i}.bullets.${bi}" rows="3">${escapeHtml(b)}</textarea></label>
      `).join("")}
      <div class="mini-actions">
        <button type="button" data-action="add-bullet" data-key="${cs.id}" data-index="${i}">Add Bullet</button>
        <button type="button" data-action="remove-item" data-key="${cs.id}" data-index="${i}">Remove Entry</button>
      </div>
    </div>
  `).join("") || `<div class="empty-state">No entries yet.</div>`;
  return `
    <div class="editor-section ${open}" data-section="${cs.id}" draggable="true">
      <div class="section-header">
        <button class="section-toggle" type="button">
          <span class="drag-handle" title="Drag to reorder">⠿</span>${escapeHtml(cs.title)}<span>${open ? "v" : ">"}</span>
        </button>
        <button class="remove-section-btn" type="button" data-action="remove-section" data-key="${cs.id}">Remove</button>
      </div>
      <div class="section-body">
        ${rows}
        <div class="mini-actions">
          <button type="button" data-action="add-item" data-key="${cs.id}">Add Entry</button>
        </div>
      </div>
    </div>`;
}

function addCustomSection() {
  const title = prompt("Section name (e.g. Volunteer Work, Publications, Awards, Languages):");
  if (!title?.trim()) return;
  const id = `cs_${Date.now()}`;
  if (!state.resume.customSections) state.resume.customSections = [];
  state.resume.customSections.push({ id, title: title.trim(), items: [{ role: "", org: "", location: "", dates: "", bullets: [""] }] });
  if (!state.sectionOrder) state.sectionOrder = [...defaultState.sectionOrder];
  state.sectionOrder.push(id);
  openSections.add(id);
  renderAll();
  persist();
}

// Field builders
function experienceFields(item, i, key) {
  return [
    inputField("Role", `resume.${key}.${i}.role`, item.role),
    inputField("Organisation", `resume.${key}.${i}.org`, item.org),
    inputField("Location", `resume.${key}.${i}.location`, item.location),
    inputField("Dates", `resume.${key}.${i}.dates`, item.dates),
    bulletsField(key, i, item.bullets),
  ].join("");
}

function educationFields(item, i, key) {
  return [
    inputField("Degree", `resume.${key}.${i}.degree`, item.degree),
    inputField("School", `resume.${key}.${i}.school`, item.school),
    inputField("Location", `resume.${key}.${i}.location`, item.location),
    inputField("Dates", `resume.${key}.${i}.dates`, item.dates),
    inputField("Details", `resume.${key}.${i}.details`, item.details),
  ].join("");
}

function projectFields(item, i, key) {
  return [
    inputField("Project", `resume.${key}.${i}.name`, item.name),
    inputField("Dates", `resume.${key}.${i}.dates`, item.dates),
    bulletsField(key, i, item.bullets),
  ].join("");
}

function certificationFields(item, i, key) {
  return [
    inputField("Certification", `resume.${key}.${i}.name`, item.name),
    inputField("Issuer", `resume.${key}.${i}.issuer`, item.issuer),
    inputField("Date", `resume.${key}.${i}.date`, item.date),
  ].join("");
}

function inputField(label, path, value) {
  return `<label>${label}<input data-path="${path}" value="${escapeAttr(value || "")}"></label>`;
}

function bulletsField(key, index, bullets = []) {
  return bullets.map((b, bi) => `
    <label>Bullet ${bi + 1}<textarea data-path="resume.${key}.${index}.bullets.${bi}" rows="3">${escapeHtml(b)}</textarea></label>
  `).join("");
}

// Section editor bindings
// Called after each renderEditors() because the DOM elements are rebuilt.
function bindSectionEditors() {
  // Collapse / expand section bodies
  document.querySelectorAll(".section-toggle").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      if (e.target.closest(".drag-handle")) return;
      const sec = btn.closest(".editor-section");
      sec.classList.toggle("open");
      const key = sec.dataset.section;
      sec.classList.contains("open") ? openSections.add(key) : openSections.delete(key);
      btn.querySelector("span:last-child").textContent = sec.classList.contains("open") ? "v" : ">";
    });
  });

  // Live data-path binding: any input/textarea with data-path writes directly
  // into the nested state object and triggers a preview re-render.
  document.querySelectorAll("[data-path]").forEach((field) => {
    field.addEventListener("input", (e) => {
      setPath(state, e.target.dataset.path, e.target.value);
      renderPreview();
      persist();
    });
  });

  // Action buttons inside section bodies (add/remove bullets/items/sections)
  document.querySelectorAll("[data-action]").forEach((btn) => {
    btn.addEventListener("click", () => handleEditorAction(btn.dataset));
  });

  // Drag-and-drop section reordering — only activates when dragging from the ⠿ handle
  document.querySelectorAll(".drag-handle").forEach((handle) => {
    handle.addEventListener("mousedown", () => { _dragFromHandle = true; });
  });

  document.querySelectorAll(".editor-section[draggable]").forEach((sec) => {
    sec.addEventListener("dragstart", (e) => {
      if (!_dragFromHandle) { e.preventDefault(); return; }
      _dragSrcKey = sec.dataset.section;
      _dragFromHandle = false;
      sec.classList.add("dragging");
      e.dataTransfer.effectAllowed = "move";
    });
    sec.addEventListener("dragend", () => {
      sec.classList.remove("dragging");
      document.querySelectorAll(".editor-section").forEach(s => s.classList.remove("drag-over"));
    });
    sec.addEventListener("dragover", (e) => {
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      document.querySelectorAll(".editor-section").forEach(s => s.classList.remove("drag-over"));
      sec.classList.add("drag-over");
    });
    sec.addEventListener("dragleave", () => sec.classList.remove("drag-over"));
    sec.addEventListener("drop", (e) => {
      e.preventDefault();
      sec.classList.remove("drag-over");
      const targetKey = sec.dataset.section;
      if (!_dragSrcKey || _dragSrcKey === targetKey) return;
      const order = [...(state.sectionOrder || defaultState.sectionOrder)];
      const fromIdx = order.indexOf(_dragSrcKey);
      const toIdx = order.indexOf(targetKey);
      if (fromIdx === -1 || toIdx === -1) return;
      order.splice(fromIdx, 1);
      order.splice(toIdx, 0, _dragSrcKey);
      state.sectionOrder = order;
      _dragSrcKey = null;
      renderEditors();
      renderPreview();
      persist();
    });
  });
}

function handleEditorAction(data) {
  const key = data.key;
  const csArr = state.resume.customSections || [];
  const cs = csArr.find(s => s.id === key);

  if (data.action === "add-skill") {
    state.resume.skills.push({ label: "New Skill Group", items: "" });
  }
  if (data.action === "add-item") {
    addItem(key);
    openSections.add(key);
  }
  if (data.action === "remove-item") {
    if (cs) cs.items.splice(Number(data.index), 1);
    else state.resume[key].splice(Number(data.index), 1);
  }
  if (data.action === "add-bullet") {
    const item = cs
      ? cs.items[Number(data.index)]
      : state.resume[key][Number(data.index)];
    item.bullets = item.bullets || [];
    item.bullets.push("");
  }
  if (data.action === "remove-section" || data.action === "delete-section") {
    const label = cs ? (cs.title || key) : key;
    if (!confirm(`Remove the "${label}" section? This cannot be undone.`)) return;
    if (cs) {
      state.resume.customSections = csArr.filter(s => s.id !== key);
    } else if (key === "summary") {
      state.resume.summary = "";
    } else if (key === "skills") {
      state.resume.skills = [];
    } else if (state.resume[key] !== undefined) {
      state.resume[key] = [];
    }
    state.sectionOrder = (state.sectionOrder || []).filter(k => k !== key);
    openSections.delete(key);
  }

  renderAll();
  persist();
}

function addItem(key) {
  const cs = (state.resume.customSections || []).find(s => s.id === key);
  if (cs) {
    cs.items.push({ role: "", org: "", location: "", dates: "", bullets: [""] });
    return;
  }
  const templates = {
    experience: { role: "", org: "", location: "", dates: "", bullets: [""] },
    education: { degree: "", school: "", location: "", dates: "", details: "" },
    projects: { name: "", dates: "", bullets: [""] },
    certifications: { name: "", issuer: "", date: "" },
  };
  if (!state.resume[key]) state.resume[key] = [];
  state.resume[key].push(structuredClone(templates[key] || { role: "", org: "", location: "", dates: "", bullets: [""] }));
}

function addExperience() {
  addItem("experience");
  openSections.add("experience");
  renderAll();
  persist();
}

// Write a value into a deeply nested path like "resume.experience.0.bullets.1"
//
// SECURITY — Prototype Pollution Guard
//
// This function is called with user-supplied `data-path` attribute values from
// HTML elements we build dynamically. A crafted resume file could (in theory)
// inject a `data-path` like "__proto__.isAdmin" into the DOM. Without the guard
// below, `setPath(obj, "__proto__.isAdmin", true)` would write to
// Object.prototype and make *every* plain object in the app suddenly have
// `.isAdmin === true` — a classic prototype pollution attack.
//
// The fix is simple: if any segment of the dot-path is a known dangerous key
// (__proto__, constructor, prototype), we log a warning and drop the write
// entirely. Legitimate paths from our own code never contain these keys.
function setPath(obj, path, value) {
  const parts = path.split(".");
  // These three keys are the known prototype-chain attack vectors in JS.
  // Using a Set for the lookup because it's O(1) and more readable than ||.
  const DANGEROUS = new Set(["__proto__", "constructor", "prototype"]);

  if (parts.some(p => DANGEROUS.has(p))) {
    // Log so a developer can see if something unexpected is happening.
    // Don't throw — a silent drop is less disruptive to the user session.
    console.warn("[setPath] Blocked potential prototype pollution attempt:", path);
    return;
  }

  let cursor = obj;
  for (const part of parts.slice(0, -1)) cursor = cursor[part];
  cursor[parts.at(-1)] = value;
}

// Resume preview
// Renders the right-side paper preview entirely from state.
// Every section in sectionOrder is rendered in order; custom sections use the
// generic experience-style renderer.
function renderPreview() {
  const { resume, design } = state;

  // Plain-text contact fields (email, phone, location)
  const textItems = [resume.contact.email, resume.contact.phone, resume.contact.location]
    .filter(Boolean)
    .map(escapeHtml);

  // Social/portfolio URLs become labeled hyperlinks so the reader sees
  // "LinkedIn" / "GitHub" / "Website" as a clickable word, not a raw URL.
  // Prepend https:// when the user typed a bare domain (linkedin.com/in/...).
  const linkItems = design.showLinks ? [
    [resume.contact.linkedin, "LinkedIn"],
    [resume.contact.github,   "GitHub"],
    [resume.contact.website,  "Website"],
  ].filter(([url]) => Boolean(url)).map(([url, label]) => {
    const href = /^https?:\/\//i.test(url) ? url : `https://${url}`;
    return `<a class="resume-link" href="${escapeAttr(href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`;
  }) : [];

  const contact = [...textItems, ...linkItems].join("<span>|</span>");

  $("resumePreview").className = "resume-paper";

  const order = state.sectionOrder || defaultState.sectionOrder;
  const sectionHtml = order.map(key => {
    switch (key) {
      case "summary":
        return section("Professional Summary", `<p>${escapeHtml(resume.summary)}</p>`);
      case "skills":
        return section("Key Skills", resume.skills.map(s =>
          `<div class="skill-row"><strong>${escapeHtml(s.label)}:</strong> ${escapeHtml(s.items)}</div>`
        ).join(""));
      case "experience":
        return section("Work Experience", (resume.experience || []).filter(e => e.role || e.org).map(renderEntry).join(""));
      case "education":
        return section("Education", (resume.education || []).filter(e => e.degree || e.school).map(renderEducation).join(""));
      case "projects":
        return section("Projects", (resume.projects || []).filter(p => p.name).map(renderProject).join(""));
      case "certifications":
        return section("Certifications", (resume.certifications || []).filter(c => c.name).map(renderCertification).join(""));
      default: {
        // Custom sections (Volunteering, Awards, Publications, etc.)
        const cs = (resume.customSections || []).find(s => s.id === key);
        if (!cs) return "";
        const items = (cs.items || []).filter(e => e.role || e.org || (e.bullets || []).some(Boolean));
        return section(cs.title, items.map(renderEntry).join(""));
      }
    }
  }).join("");

  $("resumePreview").innerHTML = `
    <header class="resume-head">
      <h1>${escapeHtml(resume.contact.name || "Your Name")}</h1>
      <div class="contact-line">${contact}</div>
    </header>
    ${sectionHtml}
  `;

  // After the DOM updates, insert visual page-break rulers and update the
  // page count badge so the user knows if they're over 1 page.
  requestAnimationFrame(addPageBreakIndicators);
}

// Wraps section HTML; returns empty string if there's nothing to show.
function section(title, html) {
  if (!stripHtml(html).trim()) return "";
  return `<section class="resume-section"><h2>${title}</h2>${html}</section>`;
}

// Entry renderers
function renderEntry(item) {
  return `
    <div class="entry">
      <div class="role-row"><span>${escapeHtml(item.role)}</span><span>${escapeHtml(item.dates)}</span></div>
      <div class="sub-row"><span>${escapeHtml(item.org)}</span><span>${escapeHtml(item.location)}</span></div>
      ${bulletList(item.bullets)}
    </div>`;
}

function renderEducation(item) {
  return `
    <div class="entry">
      <div class="role-row"><span>${escapeHtml(item.degree)}</span><span>${escapeHtml(item.dates)}</span></div>
      <div class="sub-row"><span>${escapeHtml(item.school)}</span><span>${escapeHtml(item.location)}</span></div>
      ${item.details ? `<p>${escapeHtml(item.details)}</p>` : ""}
    </div>`;
}

function renderProject(item) {
  return `
    <div class="entry">
      <div class="role-row"><span>${escapeHtml(item.name)}</span><span>${escapeHtml(item.dates)}</span></div>
      ${bulletList(item.bullets)}
    </div>`;
}

function renderCertification(item) {
  return `<p><strong>${escapeHtml(item.name)}</strong>${item.issuer ? `, ${escapeHtml(item.issuer)}` : ""}${item.date ? `, ${escapeHtml(item.date)}` : ""}</p>`;
}

function bulletList(bullets = []) {
  const clean = bullets.filter(Boolean);
  return clean.length ? `<ul>${clean.map(b => `<li>${escapeHtml(b)}</li>`).join("")}</ul>` : "";
}

// Page break indicators
// After the preview renders, this function inserts horizontal rules at every
// A4 page boundary so the user can see at a glance whether their resume fits
// on one page or flows onto a second (or third) page.
//
// CSS specifies 1in = 96px regardless of screen DPI, so A4 (11.69in tall) is
// always exactly 1122.24px in the CSS coordinate system.
function addPageBreakIndicators() {
  const paper = $("resumePreview");
  if (!paper) return;

  // Clear old indicators (they're re-built after every render)
  paper.querySelectorAll(".page-break-line").forEach(el => el.remove());

  const PAGE_H_PX = 11.69 * 96;           // A4 height in CSS pixels ≈ 1122px
  const totalHeight = paper.scrollHeight;   // actual rendered height of the paper
  const totalPages = Math.max(1, Math.ceil(totalHeight / PAGE_H_PX));

  // Insert a ruler line at each page boundary (not at the very end of the last page)
  for (let page = 1; page < totalPages; page++) {
    const line = document.createElement("div");
    line.className = "page-break-line";
    line.style.top = `${page * PAGE_H_PX}px`;
    line.setAttribute("aria-label", `Page ${page} / ${page + 1} boundary`);
    line.innerHTML = `<span class="page-break-label">Page ${page + 1} starts here</span>`;
    paper.appendChild(line);
  }

  // Update the page count badge below the paper
  const badge = $("pageCountDisplay");
  if (badge) {
    badge.textContent = totalPages === 1 ? "1 page  ✓" : `${totalPages} pages`;
    badge.className = `page-count${totalPages > 1 ? " multi-page" : ""}`;
  }
}

// Keyword coverage panel
// Scans JD keywords against the resume and shows matched/missing chips.
// No score % — just a count and chips so the user knows what to add manually.
function renderJobMatch() {
  const el = $("jobMatchDisplay");
  if (!el) return;

  const hasJd = !!(state.jobDescription && state.jobDescription.trim().length >= 30);

  if (!hasResume() || !hasJd) {
    el.innerHTML = `<div class="match-empty">${
      !hasResume()
        ? "Upload your resume first."
        : "Paste a job description to see which keywords are covered."
    }</div>`;
    return;
  }

  const resumeText = resumeToText(state.resume).toLowerCase();
  const jdText     = state.jobDescription.toLowerCase();
  const jdKeywords = extractKeywords(jdText).slice(0, 40);

  if (!jdKeywords.length) {
    el.innerHTML = `<div class="match-empty">Could not extract keywords from the job description. Try adding more detail.</div>`;
    return;
  }

  // Word-boundary matching for single-word tokens; substring for phrases.
  // Prevents "Python" from matching "Pythonic" and keeps results stable.
  const kwMatch = (kw, text) =>
    kw.includes(" ") ? text.includes(kw) : new RegExp(`\\b${escapeRegExp(kw)}\\b`).test(text);

  const matched = jdKeywords.filter(w =>  kwMatch(w, resumeText));
  const missing = jdKeywords.filter(w => !kwMatch(w, resumeText)).slice(0, 14);

  const chip = (k, cls) => `<span class="mc ${cls}">${escapeHtml(k)}</span>`;

  el.innerHTML = `
    <div class="match-count-row">
      <span class="match-count-num">${matched.length}<span class="match-count-of"> / ${jdKeywords.length}</span></span>
      <span class="match-count-label">keywords from this job description found in your resume</span>
    </div>
    ${matched.length ? `<div class="match-chips"><span class="mc-label">Found</span>${matched.slice(0,14).map(k=>chip(k,"ok")).join("")}</div>` : ""}
    ${missing.length ? `
      <div class="match-chips"><span class="mc-label">Missing</span>${missing.map(k=>chip(k,"no")).join("")}</div>
      <p class="match-disclaimer">These keywords weren't detected in your resume. Add them yourself in the Edit Resume section if they genuinely apply to your experience, they won't be added automatically unless your resume already shows clear evidence of them.</p>
    ` : `<p class="match-disclaimer match-disclaimer--good">Your resume covers all the detected keywords from this job description.</p>`}
    <div class="match-divider"></div>`;
}

function localAtsScore(resume, jobDescription) {
  const resumeText = resumeToText(resume).toLowerCase();
  const jdText = (jobDescription || "").toLowerCase();
  const hasJd = jdText.trim().length >= 30;

  const jdKeywords = hasJd ? extractKeywords(jdText).slice(0, 40) : [];
  const kwMatch = (kw, text) =>
    kw.includes(" ") ? text.includes(kw) : new RegExp(`\\b${escapeRegExp(kw)}\\b`).test(text);
  const matched = hasJd ? jdKeywords.filter(w => kwMatch(w, resumeText)) : [];
  const missing = hasJd ? jdKeywords.filter(w => !kwMatch(w, resumeText)).slice(0, 16) : [];

  const bullets = resume.experience.flatMap(e => e.bullets || []);
  const quantified = bullets.filter(b => /\d|%|\$|per month|weekly|daily|users|tickets|devices/i.test(b)).length;
  const weak = bullets.filter(b => /responsible for|helped|worked on|assisted with|various/i.test(b)).length;

  const sectionScore = [
    resume.summary,
    resume.skills.length,
    resume.experience.length,
    resume.education.length,
    resume.contact.email && resume.contact.phone,
  ].filter(Boolean).length / 5;

  const keywordScore = hasJd ? (jdKeywords.length ? matched.length / jdKeywords.length : 0) : 0;
  const proofScore = bullets.length ? Math.min(1, quantified / Math.max(3, bullets.length * 0.55)) : 0;
  const clarityScore = bullets.length ? Math.max(0.25, 1 - weak / bullets.length) : 0.4;

  // When a JD is present: keyword match heavily weighted (reflects real ATS ranking).
  // Without a JD: pure quality score based on structure, proof, and clarity.
  const score = hasJd
    ? Math.round((keywordScore * 46) + (proofScore * 22) + (clarityScore * 16) + (sectionScore * 16))
    : Math.round((proofScore * 35) + (clarityScore * 30) + (sectionScore * 35));

  const findings = [];

  // JD-specific finding: missing keywords
  if (hasJd && missing.length) {
    findings.push(finding("major", "ATS",
      `Missing or weak job keywords: ${missing.slice(0, 8).join(", ")}.`,
      "Add only the missing skills you genuinely have, inside skills and recent experience bullets."));
  }

  // General ATS: contact completeness
  if (!resume.contact.email || !resume.contact.phone) {
    findings.push(finding("major", "formatting",
      "Contact details are incomplete.",
      "Add both a professional email and phone number. ATS systems require these fields."));
  }

  // General ATS: summary
  const summaryWords = (resume.summary || "").trim().split(/\s+/).filter(Boolean).length;
  if (summaryWords < 20) {
    findings.push(finding("major", "clarity",
      summaryWords === 0 ? "Professional summary is missing." : "Professional summary is too brief.",
      "Write a 3 to 4 line summary leading with your target job title, experience level, and top 2 to 3 hard skills."));
  } else if (summaryWords > 95) {
    findings.push(finding("minor", "clarity",
      "Professional summary is too long for ATS scanning.",
      "Cut it to 3 to 4 crisp lines. ATS systems scan fast."));
  }

  // General ATS: skills section
  if (!resume.skills.length) {
    findings.push(finding("major", "ATS",
      "No dedicated skills section detected.",
      "Add a skills section. It is one of the most scanned sections in ATS systems."));
  }

  // General ATS: proof / metrics
  if (proofScore < 0.6) {
    findings.push(finding("major", "proof",
      "Bullets lack quantified achievements.",
      "Add concrete numbers: volume handled, cost saved, time reduced, users supported, tickets closed."));
  }

  // General ATS: weak phrasing
  if (weak) {
    findings.push(finding("minor", "clarity",
      `${weak} bullet${weak > 1 ? "s use" : " uses"} passive or vague phrasing.`,
      "Start each bullet with a strong past-tense action verb (Led, Built, Reduced, Deployed, Managed)."));
  }

  // General ATS: LinkedIn
  if (!resume.contact.linkedin) {
    findings.push(finding("minor", "formatting",
      "LinkedIn profile URL is missing.",
      "Add your LinkedIn URL. Most recruiters verify candidates here."));
  }

  const verdict = hasJd
    ? (score >= 82
      ? "Strong match. Address any missing keywords and add quantified proof."
      : score >= 68
        ? "Promising match but gaps need addressing before applying."
        : "Needs significant tailoring to match this job description.")
    : (score >= 75
      ? "Strong general ATS quality. Ready to be tailored for specific roles."
      : score >= 55
        ? "Decent quality. Strengthen bullets with metrics and sharpen the summary."
        : "Needs work before passing ATS filters. Focus on structure and bullet quality.");

  return {
    resume,
    score: Math.max(0, Math.min(100, score)),
    verdict,
    keywordCoverage: hasJd
      ? { matched, missing, overused: findOverused(resumeText) }
      : { matched: [], missing: [], overused: [] },
    findings,
    rewriteNotes: [],
    questions: [],
  };
}

function finding(severity, area, issue, fix) {
  return { severity, area, issue, fix, applyable: true };
}

function extractKeywords(text) {
  const words = (text.match(/[a-z][a-z0-9+#.-]{2,}/g) || []).filter(w => !stopWords.has(w) && !/^\d+$/.test(w));
  const freq = new Map();
  for (const w of words) freq.set(w, (freq.get(w) || 0) + 1);
  const phrases = ["active directory", "office 365", "customer service", "technical support", "help desk", "service desk", "ticketing system", "windows troubleshooting", "hardware troubleshooting", "linux cli", "asset management", "incident management"];
  return [...phrases.filter(p => text.includes(p)), ...[...freq.entries()].sort((a, b) => b[1] - a[1]).map(([w]) => w)]
    .filter((w, i, arr) => arr.indexOf(w) === i);
}

function findOverused(text) {
  return extractKeywords(text).filter(t => (text.match(new RegExp(`\\b${escapeRegExp(t)}\\b`, "g")) || []).length > 9).slice(0, 8);
}

// AI interaction
// Core function for all three AI modes: tailor, score, and improve.
//
// Critical fix: selectedFeedback indices are resolved against the CURRENT
// state.analysis.findings BEFORE we overwrite state.analysis with the local
// score (which has different findings in a different order). The old code did
// this the wrong way around, meaning "Apply Feedback" sent the wrong items.
async function runAi(mode) {

  // STEP 1 — Capture the user's selected feedback items while analysis still
  //          contains the findings that were actually shown to the user.
  const selectedFeedback = (state.analysis?.findings || [])
    .filter((_, i) => state.selectedFeedback.includes(i));

  // STEP 2 — Compute a local score to send as context alongside the AI call.
  //          We don't render this immediately in "improve" mode because the
  //          existing AI analysis is still what the user is looking at.
  const localScore = localAtsScore(state.resume, state.jobDescription);

  // Show a spinning save indicator while the request is in flight
  setBusy(true, mode === "improve" ? "Applying feedback…" : "Tailoring with AI…");

  // Preserve customSections so they survive the AI response merge.
  // The AI might return them (good) or omit them (we keep originals).
  const originalCustomSections = structuredClone(state.resume.customSections || []);

  try {
    const res = await fetch("/api/ai", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        mode,
        resume: state.resume,
        jobDescription: state.jobDescription,
        localScore,
        selectedFeedback,
      }),
    });

    const json = await res.json();
    if (!res.ok) throw new Error(json.error || "AI request failed.");

    // STEP 3 — If the AI returned a rewritten resume, apply it to state.
    //          We merge against defaultState (not state.resume) so the schema
    //          is clean, then restore customSections from the AI response or —
    //          if the AI omitted them — from the originals we saved above.
    if ((mode === "tailor" || mode === "improve") && json.resume) {
      const aiResume = json.resume;

      // Decide which customSections to use: AI's returned set (if non-empty)
      // takes priority; fall back to what the user had before.
      const mergedCustomSections =
        (aiResume.customSections && aiResume.customSections.length > 0)
          ? aiResume.customSections
          : originalCustomSections;

      state.resume = merge(defaultState.resume, aiResume);
      state.resume.customSections = mergedCustomSections;
    }

    state.analysis = json;
    // Mark that this analysis is the result of an "Apply Feedback" run so the
    // feedback panel can switch to the post-apply summary view (no pending cards).
    if (mode === "improve") state.analysis._appliedRun = true;
    state.selectedFeedback = [];

    renderAll();
    persist();

    // STEP 4 — Flash the resume paper green to give the user clear proof that
    //          content was modified, then show what changed via a toast.
    if (mode === "tailor" || mode === "improve") {
      const paper = $("resumePreview");
      paper.classList.remove("ai-applied");
      // Force reflow so removing then adding the class restarts the animation
      void paper.offsetWidth;
      paper.classList.add("ai-applied");

      const changeCount = (json.rewriteNotes || []).length;
      const label = mode === "improve" ? "Feedback applied" : "Resume tailored";
      showToast(
        changeCount > 0
          ? `${label}: ${changeCount} change${changeCount !== 1 ? "s" : ""} made. See "Rewrite notes" in the panel.`
          : `${label}. Review the preview to see your updated resume.`,
        "success",
        7000
      );
    }

  } catch (err) {
    // Detect Cerebras rate-limit errors (HTTP 429 or the message text they return)
    // and surface a friendlier "wait a minute" prompt instead of a generic error.
    const isRateLimit = /rate.?limit|too many request|429/i.test(err.message);
    const userMsg = isRateLimit
      ? "Too many requests. Please wait and try again later."
      : err.message;

    state.analysis = {
      ...localScore,
      findings: [
        finding("critical", "risk", userMsg,
          isRateLimit
            ? "Wait ~60 seconds, then click Tailor with AI again."
            : "Check your .env key, model name, and internet connection.")
      ].concat(localScore.findings || []),
    };
    renderAll();
    showToast(userMsg, "error", isRateLimit ? 12000 : 9000);
  } finally {
    setBusy(false);
  }
}

// Disable/re-enable AI buttons during a request.
function setBusy(isBusy, label = "") {
  for (const id of ["aiTailorBtn", "applyFeedbackBtn"]) {
    const el = $(id);
    if (!el) continue;
    el.disabled = isBusy;
    el._busyLocked = isBusy;
    if (isBusy) el.textContent = label || "Working…";
  }
  if (!isBusy) {
    const t = $("aiTailorBtn");
    if (t) t.textContent = "Tailor with AI";
    const a = $("applyFeedbackBtn");
    if (a) a.textContent = "Apply Selected";
    updateButtonStates();
  }
}

// Feedback list
// Renders AI findings (checkboxes), rewrite notes, and questions.
function renderFeedback() {
  const analysis = state.analysis;
  if (!analysis) {
    $("feedbackList").innerHTML = hasResume()
      ? `<div class="empty-state">Paste a job description and click <strong>Tailor with AI</strong> to get recommendations.</div>`
      : "";
    return;
  }

  // Post-apply view (after "Apply Feedback")
  // Summary only — no pending-change cards.
  if (analysis._appliedRun) {
    const keyword = analysis.keywordCoverage || {};
    const hasJd = !!(state.jobDescription && state.jobDescription.trim().length >= 30);

    const notes = (analysis.rewriteNotes || []).length
      ? `<div class="feedback-item rewrite-notes">
          <div class="feedback-top"><span class="badge applied-badge">✓ Changes applied to your resume</span></div>
          ${(analysis.rewriteNotes || []).map(n => `<p>• ${escapeHtml(n)}</p>`).join("")}
        </div>`
      : `<div class="feedback-item rewrite-notes">
          <div class="feedback-top"><span class="badge applied-badge">✓ Feedback applied</span></div>
          <p>All selected changes have been written into your resume. Review the preview on the right.</p>
        </div>`;

    const keywordBlock = hasJd
      ? `<div class="feedback-item">
          <div class="feedback-top"><span class="badge">Keyword coverage vs. job description</span></div>
          <p><strong>Matched:</strong> ${(keyword.matched || []).slice(0, 16).join(", ") || "None detected"}</p>
          <p><strong>Still missing:</strong> ${(keyword.missing || []).slice(0, 16).join(", ") || "None. Great match!"}</p>
        </div>`
      : "";

    const unapplyable = (analysis.findings || []).filter(f => f.applyable === false);
    const unapplyableHtml = unapplyable.length
      ? `<div class="feedback-item minor">
          <div class="feedback-top"><span class="badge">Could not apply:  no evidence found in resume</span></div>
          ${unapplyable.map(f => `<p>• ${escapeHtml(f.issue || "")}</p>`).join("")}
        </div>`
      : "";

    const questions = (analysis.questions || []).length
      ? `<div class="feedback-item major">
          <div class="feedback-top"><span class="badge">Facts that would strengthen your resume</span></div>
          ${(analysis.questions || []).map(q => `<p>${escapeHtml(q)}</p>`).join("")}
        </div>`
      : "";

    $("feedbackList").innerHTML = notes + keywordBlock + unapplyableHtml + questions;
    return;
  }

  // Normal findings view (after "Tailor with AI")
  const findings = analysis.findings || [];
  const keyword = analysis.keywordCoverage || {};
  const hasJd = !!(state.jobDescription && state.jobDescription.trim().length >= 30);

  const keywordBlock = (hasJd && ((keyword.matched || []).length || (keyword.missing || []).length))
    ? `<div class="feedback-item">
        <div class="feedback-top"><span class="badge">Keyword coverage vs. job description</span></div>
        <p><strong>Matched:</strong> ${(keyword.matched || []).slice(0, 16).join(", ") || "None yet"}</p>
        <p><strong>Missing:</strong> ${(keyword.missing || []).slice(0, 16).join(", ") || "No obvious misses"}</p>
      </div>`
    : "";

  const items = findings.map((item, i) => {
    const applyable = item.applyable !== false;
    const hasNumber = /\b\d[\d,]*(\.\d+)?[kKmM%x+]?\b/.test(item.fix || "");
    const disclaimer = hasNumber
      ? `<p class="number-disclaimer">Number is auto-generated. Review and edit it before accepting.</p>`
      : "";
    return `
    <div class="feedback-item ${escapeAttr(item.severity || "minor")}">
      <div class="feedback-top">
        <span class="badge">${escapeHtml(item.severity || "minor")} / ${escapeHtml(item.area || "general")}</span>
        ${applyable ? `<label class="check-label"><input type="checkbox" data-feedback-index="${i}" ${state.selectedFeedback.includes(i) ? "checked" : ""}> Apply</label>` : ""}
      </div>
      <p><strong>Issue:</strong> ${escapeHtml(item.issue || "")}</p>
      <p><strong>Fix:</strong> ${escapeHtml(item.fix || "")}</p>
      ${disclaimer}
    </div>`;
  }).join("");

  const notes = (analysis.rewriteNotes || []).length ? `
    <div class="feedback-item rewrite-notes">
      <div class="feedback-top"><span class="badge applied-badge">✓ Changes applied</span></div>
      ${(analysis.rewriteNotes || []).map(n => `<p>• ${escapeHtml(n)}</p>`).join("")}
    </div>` : "";

  const questions = (analysis.questions || []).length ? `
    <div class="feedback-item major">
      <div class="feedback-top"><span class="badge">Facts that would strengthen your resume</span></div>
      ${(analysis.questions || []).map(q => `<p>${escapeHtml(q)}</p>`).join("")}
    </div>` : "";

  $("feedbackList").innerHTML = keywordBlock + items + notes + questions;

  document.querySelectorAll("[data-feedback-index]").forEach((box) => {
    box.addEventListener("change", (e) => {
      const i = Number(e.target.dataset.feedbackIndex);
      state.selectedFeedback = e.target.checked
        ? [...new Set(state.selectedFeedback.concat(i))]
        : state.selectedFeedback.filter(x => x !== i);
      persist();
      updateButtonStates();
    });
  });
}

// Text utilities
// Concatenate all text-bearing fields into a single string for keyword matching.
// Custom sections are included so Volunteering/Publications keywords count too.
function resumeToText(resume) {
  const customText = (resume.customSections || []).map(cs =>
    `${cs.title} ${(cs.items || []).map(i => `${i.role} ${i.org} ${(i.bullets || []).join(" ")}`).join(" ")}`
  ).join(" ");

  return [
    Object.values(resume.contact || {}).join(" "),
    resume.summary,
    (resume.skills || []).map(s => `${s.label} ${s.items}`).join(" "),
    (resume.experience || []).map(e => `${e.role} ${e.org} ${(e.bullets || []).join(" ")}`).join(" "),
    (resume.education || []).map(e => `${e.degree} ${e.school} ${e.details}`).join(" "),
    (resume.projects || []).map(p => `${p.name} ${(p.bullets || []).join(" ")}`).join(" "),
    (resume.certifications || []).map(c => `${c.name} ${c.issuer}`).join(" "),
    customText,
  ].join(" ");
}

// File upload
// The file input's change event handler — validates and dispatches to handleFileLoad.
async function importFile(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  await handleFileLoad(file);
  e.target.value = ""; // reset so the same file can be re-selected
}

// Update the drop zone visual state
function setDropZoneState(cls, label) {
  const dz = $("dropZone");
  dz.classList.remove("parsing", "done");
  if (cls) dz.classList.add(cls);
  const lbl = $("dropLabel");
  if (lbl && label) lbl.textContent = label;
}

// PDF-only file handler — drops DOCX/TXT support (PDF is the only accepted format).
async function handleFileLoad(file) {
  const ext  = file.name.toLowerCase().split(".").pop();
  const mime = file.type || "";
  const DEFAULT_LABEL = "Drop or Browse PDF";

  if (mime !== "application/pdf" && ext !== "pdf") {
    showToast(`Only PDF files are accepted. Please upload a .pdf file.`, "error", 7000);
    return;
  }

  setDropZoneState("parsing", "Reading PDF…");
  try {
    const buffer = await file.arrayBuffer();
    $("dropLabel").textContent = "Parsing with AI…";
    const res = await fetch("/api/parse-resume", {
      method: "POST",
      headers: { "content-type": "application/pdf", "x-filename": file.name },
      body: buffer,
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || "PDF parse failed.");
    applyParsedResume(json);
    setDropZoneState("done", "Resume loaded");
    setTimeout(() => setDropZoneState(null, DEFAULT_LABEL), 2500);
    showToast("Resume parsed and loaded review sections in Edit Resume to make any changes if missed.", "success");
  } catch (err) {
    setDropZoneState(null, DEFAULT_LABEL);
    showToast("Could not parse PDF: " + err.message, "error", 8000);
  }
}

// Apply a parsed resume object to state. Ensures customSections have IDs
// and updates sectionOrder to include any new custom section IDs.
function applyParsedResume(json) {
  // Merge into the blank template so every field has a default value
  state.resume = merge(blankState().resume, json);

  // Make sure every custom section has a stable ID
  state.resume.customSections = (state.resume.customSections || []).map(cs => ({
    ...cs,
    id: cs.id && String(cs.id).startsWith("cs_") ? cs.id : `cs_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
  }));

  // Reset sectionOrder to the built-in defaults plus any new custom sections
  state.sectionOrder = [...defaultState.sectionOrder];
  for (const cs of state.resume.customSections) {
    state.sectionOrder.push(cs.id);
  }

  openSections.add("summary");
  openSections.add("experience");
  state.analysis = null;
  state.selectedFeedback = [];
  renderAll();
  persist();
}

// Escape / sanitise helpers
function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttr(value = "") {
  return escapeHtml(value).replaceAll("\n", " ");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function stripHtml(value) {
  return value.replace(/<[^>]+>/g, " ");
}

function safeFileName(value) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "resume";
}

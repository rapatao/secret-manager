const editForm = () => document.getElementById("edit-keys");

function pendingChanges() {
  const form = editForm();
  const changes = new Map();
  for (const row of document.querySelectorAll("tr[data-key]")) {
    const key = row.dataset.key;
    const value = row.querySelector("textarea");
    if (!row.querySelector('input[name="delete"]').disabled) {
      changes.set(key, { op: "-", before: value.defaultValue });
    } else if (value.value !== value.defaultValue) {
      changes.set(key, { op: "~", before: value.defaultValue, after: value.value });
    }
  }
  for (const row of form.querySelectorAll(".new-key")) {
    const key = row.querySelector('input[name="new-key"]').value;
    if (key !== "") changes.set(key, { op: "+", after: row.querySelector("textarea").value });
  }
  return [...changes].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}

function checkNewKeys() {
  const taken = new Set([...document.querySelectorAll("tr[data-key]")].map((row) => row.dataset.key));
  for (const input of editForm().querySelectorAll('input[name="new-key"]')) {
    const key = input.value;
    input.setCustomValidity(taken.has(key) ? `Key ${key} already exists` : "");
    taken.add(key);
  }
}

function refreshSave() {
  const form = editForm();
  if (!form) return;
  checkNewKeys();
  for (const row of document.querySelectorAll("tr[data-key]")) {
    const value = row.querySelector("textarea");
    row.classList.toggle("edited", value.value !== value.defaultValue);
  }
  const empty = document.querySelector("tr.no-keys");
  if (empty) empty.hidden = form.querySelector(".new-key") !== null;
  form.querySelector('button[type="submit"]').disabled = pendingChanges().length === 0 || !form.checkValidity();
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

function randomValue(length = 32) {
  let out = "";
  while (out.length < length) {
    for (const b of crypto.getRandomValues(new Uint8Array(length))) {
      if (b < 248 && out.length < length) out += alphabet[b % alphabet.length];
    }
  }
  return out;
}

const opClass = { "+": "add", "-": "del", "~": "mod" };

function cell(row, text) {
  const td = row.insertCell();
  if (text === undefined) return;
  const code = document.createElement("code");
  code.textContent = text;
  td.append(code);
}

function review(changes) {
  const dialog = document.getElementById("review-save");
  const rows = dialog.querySelector("tbody");
  rows.replaceChildren();
  for (const [key, c] of changes) {
    const row = rows.insertRow();
    row.className = opClass[c.op];
    row.insertCell().textContent = c.op;
    cell(row, key);
    cell(row, c.before);
    cell(row, c.after);
  }
  dialog.returnValue = "";
  dialog.showModal();
  return dialog;
}

function submitEdits(form) {
  for (const row of document.querySelectorAll("tr[data-key]")) {
    const value = row.querySelector("textarea");
    if (!row.querySelector('input[name="delete"]').disabled || value.value === value.defaultValue) {
      value.disabled = value.previousElementSibling.disabled = true;
    }
  }
  form.append(Object.assign(document.createElement("input"), { type: "hidden", name: "confirm", value: "yes" }));
  form.submit();
}

document.addEventListener("click", async (e) => {
  const opener = e.target.closest("button[commandfor]");
  if (opener && !("command" in HTMLButtonElement.prototype)) {
    document.getElementById(opener.getAttribute("commandfor")).showModal();
    return;
  }
  if (e.target.closest("button.add-key")) {
    const row = document.getElementById("new-key").content.firstElementChild.cloneNode(true);
    editForm().querySelector(".new-keys").append(row);
    row.querySelector("input").focus();
    refreshSave();
    return;
  }
  const remove = e.target.closest("button.remove-key");
  if (remove) {
    remove.closest(".new-key").remove();
    refreshSave();
    return;
  }
  const del = e.target.closest("button.delete-key");
  if (del) {
    const row = del.closest("tr");
    const staged = row.querySelector('input[name="delete"]');
    staged.disabled = !staged.disabled;
    row.classList.toggle("staged-delete", !staged.disabled);
    del.textContent = staged.disabled ? "Delete" : "Undo";
    refreshSave();
    return;
  }
  const generate = e.target.closest("button.generate");
  if (generate) {
    const value = generate.closest("td, .new-key").querySelector("textarea");
    value.value = randomValue();
    value.dispatchEvent(new Event("input", { bubbles: true }));
    return;
  }
  const copy = e.target.closest("button.copy");
  if (!copy) return;
  const source = copy.dataset.copy ? document.getElementById(copy.dataset.copy) : copy.closest("tr").querySelector("textarea");
  await navigator.clipboard.writeText(source.value);
  copy.textContent = "Copied";
  setTimeout(() => (copy.textContent = "Copy"), 1500);
});

document.addEventListener("input", (e) => {
  if (e.target.id === "path-search") {
    const query = e.target.value;
    for (const rows of document.querySelectorAll("tbody:has(tr[data-path])")) {
      let shown = 0;
      for (const row of rows.querySelectorAll("tr[data-path]")) {
        row.hidden = !row.dataset.path.includes(query);
        if (!row.hidden) shown++;
      }
      rows.querySelector("tr.no-match").hidden = shown > 0;
    }
    return;
  }
  if (!e.target.form || e.target.form !== editForm()) return;
  refreshSave();
  if (e.target.name === "new-key" && e.target.validationMessage.includes("already exists")) e.target.reportValidity();
});

document.addEventListener("submit", (e) => {
  const form = e.target;
  if (form !== editForm()) return;
  e.preventDefault();
  const changes = pendingChanges();
  if (changes.length === 0) return;
  const dialog = review(changes);
  dialog.onclose = () => {
    if (dialog.returnValue === "save") submitEdits(form);
  };
});

document.addEventListener("submit", (e) => {
  const form = e.target;
  if (form.id !== "create-path" || form.elements.confirm) return;
  e.preventDefault();
  const path = form.elements.path.value;
  if ([...document.querySelectorAll("#paths tr[data-path]")].some((row) => row.dataset.path === path)) {
    location.href = "/secrets/path?path=" + encodeURIComponent(path);
    return;
  }
  const dialog = document.getElementById("confirm-create");
  dialog.querySelector(".new-path").textContent = path;
  dialog.returnValue = "";
  dialog.onclose = () => {
    if (dialog.returnValue !== "create") return;
    form.append(Object.assign(document.createElement("input"), { type: "hidden", name: "confirm", value: "yes" }));
    form.submit();
  };
  dialog.showModal();
});

const keptExpiry = (select) => select.options[0].text.replace(/^Keep current \((.*)\)$/, "$1");

function grantSummary(form) {
  const expires = form.elements.expires;
  const label = {
    keep: () => keptExpiry(expires),
    custom: () => form.elements["expires-date"].value + " (end of day, UTC)",
  }[expires.value];
  return {
    Path: form.elements.path.value,
    Access: form.elements["read-only"].checked ? "read-only" : "read-write",
    Expires: label ? label() : expires.selectedOptions[0].text,
    "Offline cache": form.elements["cache-max-age"].selectedOptions[0].text,
    "Allowed from": form.elements["allowed-from"].value.trim() || "any",
  };
}

function confirmIntegration(form, { title, question, button, current, onCancel }) {
  const dialog = document.getElementById("confirm-integration");
  dialog.querySelector(".confirm-title").textContent = title;
  dialog.querySelector(".confirm-question").textContent = question;
  dialog.querySelector(".confirm-button").textContent = button;
  const table = dialog.querySelector("table");
  table.toggleAttribute("data-create", !current);
  const rows = table.querySelector("tbody");
  rows.replaceChildren();
  for (const [field, value] of Object.entries(grantSummary(form))) {
    const row = rows.insertRow();
    row.insertCell().textContent = field;
    row.insertCell().className = "current";
    if (current) {
      row.cells[1].textContent = current[field];
      row.classList.toggle("changed", current[field] !== value);
    }
    row.insertCell().textContent = value;
  }
  confirming = { form, onCancel };
  dialog.showModal();
}

let confirming = null;

function settleConfirm(confirmed) {
  const pending = confirming;
  confirming = null;
  if (!pending) return;
  if (!confirmed) {
    pending.onCancel?.();
    return;
  }
  pending.form.append(Object.assign(document.createElement("input"), { type: "hidden", name: "confirm", value: "yes" }));
  pending.form.submit();
}

document.getElementById("confirm-integration")?.addEventListener("cancel", () => settleConfirm(false));

function discardEdit(form) {
  form.reset();
  form.closest("dialog").close();
}

function editCurrent(form) {
  const d = form.dataset;
  return { Path: d.path, Access: d.access, Expires: keptExpiry(form.elements.expires), "Offline cache": d.cache, "Allowed from": d.allowed };
}

function editChanged(form) {
  const current = editCurrent(form);
  const next = grantSummary(form);
  return Object.keys(current).some((field) => current[field] !== next[field]);
}

let discarding = null;

function requestDiscard(form) {
  if (!editChanged(form)) {
    discardEdit(form);
    return;
  }
  discarding = form;
  const dialog = document.getElementById("discard-edit");
  dialog.querySelector(".discard-name").textContent = form.dataset.name;
  dialog.showModal();
}

for (const form of document.querySelectorAll("form.edit-integration")) {
  form.closest("dialog").addEventListener("cancel", (e) => {
    e.preventDefault();
    requestDiscard(form);
  });
}

document.addEventListener("submit", (e) => {
  const form = e.target;
  if (form.closest("#confirm-integration")) {
    settleConfirm(e.submitter?.value === "confirm");
    return;
  }
  if (form.closest("#discard-edit")) {
    if (e.submitter?.value === "discard" && discarding) discardEdit(discarding);
    return;
  }
  if (form.elements.confirm) return;
  const cancel = e.submitter?.getAttribute("formmethod") === "dialog";
  if (cancel && form.classList.contains("edit-integration")) {
    e.preventDefault();
    requestDiscard(form);
    return;
  }
  if (cancel) return;
  if (form.id === "create-integration") {
    e.preventDefault();
    const name = form.elements.name.value;
    confirmIntegration(form, { title: "Create integration", question: `Create integration ${name} with this access?`, button: "Create" });
  } else if (form.classList.contains("edit-integration")) {
    e.preventDefault();
    const d = form.dataset;
    if (!editChanged(form)) {
      discardEdit(form);
      return;
    }
    confirmIntegration(form, {
      onCancel: () => discardEdit(form),
      title: "Save changes",
      question: `Change the access of integration ${d.name}? Clients using its token get it on their next request.`,
      button: "Save",
      current: editCurrent(form),
    });
  }
});

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
  const empty = document.querySelector("tr.no-keys");
  if (empty) empty.hidden = form.querySelector(".new-key") !== null;
  form.querySelector('button[type="submit"]').disabled = pendingChanges().length === 0 || !form.checkValidity();
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
  const copy = e.target.closest("button.copy");
  if (!copy) return;
  await navigator.clipboard.writeText(copy.closest("tr").querySelector("textarea").value);
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
    location.href = "/path?path=" + encodeURIComponent(path);
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

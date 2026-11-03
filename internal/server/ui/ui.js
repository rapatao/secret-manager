document.addEventListener("click", async (e) => {
  const button = e.target.closest("button.copy");
  if (!button) return;
  await navigator.clipboard.writeText(button.closest("tr").querySelector("textarea").value);
  button.textContent = "Copied";
  setTimeout(() => (button.textContent = "Copy"), 1500);
});

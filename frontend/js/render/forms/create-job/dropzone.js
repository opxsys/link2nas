export function bindTorrentDropzone(container) {
  const zone = container.querySelector(".torrent-dropzone");
  const input = zone?.querySelector('input[name="torrent_file"]');
  if (!zone || !input) return;

  input.addEventListener("click", (e) => e.stopPropagation());

  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("is-dragover");
  });

  zone.addEventListener("dragleave", (e) => {
    if (zone.contains(e.relatedTarget)) return;
    zone.classList.remove("is-dragover");
  });

  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("is-dragover");

    const torrentFiles = Array.from(e.dataTransfer.files).filter((f) =>
      f.name.toLowerCase().endsWith(".torrent")
    );
    if (torrentFiles.length === 0) return;
    if (typeof DataTransfer === "undefined") return;

    const dt = new DataTransfer();
    for (const file of torrentFiles) dt.items.add(file);
    input.files = dt.files;
    input.dispatchEvent(new Event("change", { bubbles: true }));
  });
}

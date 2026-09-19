const form = document.querySelector("#search");
const query = document.querySelector("#query");
const list = document.querySelector("#resultList");
const status = document.querySelector("#status");

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const q = query.value.trim();

  if (!q) {
    status.textContent = "Enter something to search for.";
    return;
  }

  status.textContent = "Searching…";
  list.textContent = "Loading…";

  try {
    const response = await fetch(
      "/api/search?q=" + encodeURIComponent(q)
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        data.error || "Search failed."
      );
    }

    const results = Array.isArray(data.results)
      ? data.results
      : [];

    if (results.length === 0) {
      list.textContent = "No results.";
      status.textContent = "Search complete.";
      return;
    }

    list.innerHTML = results
      .map((result) => {
        const title = escapeHtml(result.title || "Untitled");
        const url = escapeHtml(result.url || "#");
        const snippet = escapeHtml(result.snippet || "");

        return `
          <div class="result">
            <a
              href="${url}"
              target="_blank"
              rel="noopener noreferrer"
            >
              ${title}
            </a>

            <small>
              ${snippet}
            </small>
          </div>
        `;
      })
      .join("");

    status.textContent = "Search complete.";
  } catch (error) {
    console.error(error);

    status.textContent =
      error instanceof Error
        ? error.message
        : "Search failed.";

    list.textContent =
      "The search service is unavailable.";
  }
});

function escapeHtml(value) {
  return String(value).replace(
    /[&<>"']/g,
    (character) => {
      const entities = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      };

      return entities[character];
    }
  );
}

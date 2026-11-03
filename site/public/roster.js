// Search, filter and sort for the server roster (/servers/).
//
// A real file in `public/`, not an inline script, for the same reason as
// ledger.js: the CSP is `script-src 'self'`, and Astro would inline a small
// module into the page where the policy silently blocks it. The controls ship
// `hidden`; with no script the reader has the whole list in name order and no
// control that does nothing.
//
// ⚠ AN UNASSESSED AXIS SORTS LAST, IN BOTH DIRECTIONS. Treating it as 0 would
// put a server nobody measured at the top of a "lowest first" list — the
// accusation CLAUDE.md's "Unassessed is not zero" forbids — and treating it as
// 100 would hide it at the top of "highest first". So it is neither, it is
// listed after every scored row, and the status line says how many.

const controls = document.querySelector(".roster-controls");
const list = document.querySelector(".roster");

if (controls && list) {
  const rows = [...list.children];
  const input = controls.querySelector('input[name="q"]');
  const show = controls.querySelector('select[name="show"]');
  const buttons = [...controls.querySelectorAll(".roster-sort-axis")];
  const status = controls.querySelector(".roster-status");
  const empty = controls.querySelector(".roster-empty");
  const emptyText = controls.querySelector(".roster-empty-text");
  const clear = controls.querySelector(".roster-clear");

  const params = new URLSearchParams(window.location.search);
  const state = {
    q: params.get("q") ?? "",
    show: params.get("show") ?? "all",
    sort: params.get("sort") ?? "",
    dir: params.get("dir") === "high" ? "high" : "low",
  };
  if (!buttons.some((b) => b.dataset.axis === state.sort)) state.sort = "";
  if (![...show.options].some((o) => o.value === state.show)) state.show = "all";
  input.value = state.q;
  show.value = state.show;

  const score = (row, axis) => {
    const raw = row.getAttribute(`data-score-${axis}`);
    return raw === "" || raw === null ? null : Number(raw);
  };
  const weight = (row, axis) => Number(row.getAttribute(`data-weight-${axis}`) || 0);

  const visible = (row) => {
    if (state.q && !row.dataset.name.includes(state.q.trim().toLowerCase())) return false;
    if (state.show === "read") return row.dataset.source === "read";
    if (state.show === "unread") return row.dataset.source === "unread";
    if (state.show === "noted") return row.dataset.noted === "true";
    return true;
  };

  const compare = (a, b) => {
    if (!state.sort) return 0; // rows keeps the page's own name order
    const sa = score(a, state.sort);
    const sb = score(b, state.sort);
    if (sa === null || sb === null) return (sa === null) - (sb === null);
    if (sa !== sb) return state.dir === "low" ? sa - sb : sb - sa;
    // Equal scores: the one measured more fully first — its number says more.
    return weight(b, state.sort) - weight(a, state.sort);
  };

  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  const apply = () => {
    const ordered = [...rows].sort(compare); // stable: ties keep name order
    let shown = 0;
    let unscored = 0;
    for (const row of ordered) {
      const on = visible(row);
      row.hidden = !on;
      if (on) {
        shown += 1;
        if (state.sort && score(row, state.sort) === null) unscored += 1;
      }
      list.append(row);
    }

    for (const b of buttons) {
      const active = b.dataset.axis === state.sort;
      b.setAttribute("aria-pressed", String(active));
      b.querySelector(".roster-sort-dir").textContent = active ? (state.dir === "low" ? "▴" : "▾") : "";
      b.title = active
        ? `Sorted by ${b.dataset.name}, ${state.dir === "low" ? "lowest" : "highest"} first. Click for ${state.dir === "low" ? "highest first" : "name order"}.`
        : `Sort by ${b.dataset.name}, lowest first`;
    }

    const active = buttons.find((b) => b.dataset.axis === state.sort);
    let text = `${shown} of ${rows.length} servers shown`;
    text += active
      ? `, sorted by ${active.dataset.name} from ${state.dir === "low" ? "lowest" : "highest"}.`
      : ", in name order.";
    if (active && unscored) {
      text += ` ${plural(unscored, "has", "have")} no ${active.dataset.name} score and ${unscored === 1 ? "is" : "are"} listed last — not assessed, which is not zero.`;
    }
    status.textContent = text;

    empty.hidden = shown > 0;
    if (!shown) {
      emptyText.textContent = state.q
        ? `No server shown here has “${state.q.trim()}” in its name.`
        : "No server matches this filter.";
    }

    const next = new URLSearchParams();
    if (state.q.trim()) next.set("q", state.q.trim());
    if (state.show !== "all") next.set("show", state.show);
    if (state.sort) {
      next.set("sort", state.sort);
      next.set("dir", state.dir);
    }
    const query = next.toString();
    window.history.replaceState(null, "", query ? `?${query}` : window.location.pathname);
  };

  input.addEventListener("input", () => {
    state.q = input.value;
    apply();
  });
  show.addEventListener("change", () => {
    state.show = show.value;
    apply();
  });
  for (const b of buttons) {
    // Off → lowest first → highest first → off (name order).
    b.addEventListener("click", () => {
      if (state.sort !== b.dataset.axis) {
        state.sort = b.dataset.axis;
        state.dir = "low";
      } else if (state.dir === "low") {
        state.dir = "high";
      } else {
        state.sort = "";
      }
      apply();
    });
  }
  clear.addEventListener("click", () => {
    state.q = "";
    state.show = "all";
    input.value = "";
    show.value = "all";
    apply();
    input.focus();
  });

  controls.hidden = false;
  apply();
}

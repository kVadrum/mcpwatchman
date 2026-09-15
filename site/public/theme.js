// Theme selection: auto (follow the OS), dark, or light.
//
// ⚠ THIS FILE IS LOADED SYNCHRONOUSLY FROM <head>, AND BOTH HALVES OF THAT ARE
// LOAD-BEARING.
//
// `public/` rather than an inline <script>, for the same reason `ledger.js`
// lives here: the CSP is `script-src 'self'` with no 'unsafe-inline', and the
// usual pre-paint theme snippet — an inline script in <head> — is blocked. It
// fails the way inline scripts always fail under a strict policy: the page
// renders perfectly and only the behaviour goes missing, so the flash it exists
// to prevent comes back with nothing reporting why.
//
// No `defer` and no `async`, because the one job of the first block below is to
// run BEFORE the first paint. A deferred script applies the stored theme after
// the page has already painted in the other one, which is the flash.
//
// The site is still correct with JavaScript switched off entirely: the CSS
// carries a `prefers-color-scheme` block, so a no-JS visitor gets the theme
// their system asks for. This file adds the explicit OVERRIDE, and nothing else
// — which is why the control it drives stays `hidden` until it is wired up.

// Wrapped: a classic script's top-level `const` lands in the shared global
// lexical environment, where a same-named binding in another classic script
// is a hard error rather than a shadow.
(() => {
  const STORAGE_KEY = "mcpwatchman-theme";
  const GROUND = { dark: "#10151B", light: "#CCD3DB" };

  // localStorage throws rather than returning null in some privacy modes, and a
  // theme preference is not worth failing a page load over.
  function stored() {
    try {
      const value = localStorage.getItem(STORAGE_KEY);
      return value === "dark" || value === "light" ? value : null;
    } catch {
      return null;
    }
  }

  function remember(choice) {
    try {
      if (choice === "auto") localStorage.removeItem(STORAGE_KEY);
      else localStorage.setItem(STORAGE_KEY, choice);
    } catch {
      // A session that cannot persist still switches; it just forgets.
    }
  }

  // `data-theme` is absent for auto, which is what lets the CSS media query stay
  // in charge — the light block is guarded `:root:not([data-theme="dark"])`, so
  // removing the attribute hands control back rather than pinning a value.
  function apply(choice) {
    const root = document.documentElement;
    if (choice === "auto") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", choice);
    paintBrowserChrome(choice);
  }

  // The two <meta name="theme-color"> tags are media-scoped so the browser
  // chrome matches the system theme with no script at all. An explicit choice has
  // to override that, and the only way to say so in markup is to make one tag
  // match everything and the other match nothing.
  function paintBrowserChrome(choice) {
    const tags = document.querySelectorAll('meta[name="theme-color"][data-scheme]');
    for (const tag of tags) {
      const scheme = tag.dataset.scheme;
      if (choice === "auto") tag.media = `(prefers-color-scheme: ${scheme})`;
      else tag.media = scheme === choice ? "all" : "not all";
      tag.content = GROUND[scheme];
    }
  }

  // ── before first paint ──────────────────────────────────────────────────────
  // The meta tags are authored ABOVE this script, so they already exist here —
  // which is why the browser-chrome colour can be corrected in the same block.
  // Leaving it to `wire()` at DOMContentLoaded meant a visitor whose stored
  // choice opposes their OS setting got the page in one theme and the browser's
  // own chrome in the other until the DOM finished parsing: the exact flash
  // this block exists to prevent, surviving in the one surface CSS cannot reach.
  const initial = stored();
  if (initial) {
    document.documentElement.setAttribute("data-theme", initial);
    paintBrowserChrome(initial);
  }

  // ── after the DOM exists: reveal and wire the control ───────────────────────
  function wire() {
    const control = document.querySelector(".theme");
    if (!control) return;

    const choice = stored() ?? "auto";
    const selected = control.querySelector(`input[value="${choice}"]`);
    if (selected) selected.checked = true;
    paintBrowserChrome(choice);

    control.addEventListener("change", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLInputElement) || !target.checked) return;
      remember(target.value);
      apply(target.value);
    });

    // Hidden in the markup, not here: a control that cannot work without this
    // file should not be on the page when this file has not run. Revealing it is
    // the last thing, so it never appears in a state it cannot honour.
    control.hidden = false;
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire, { once: true });
  } else {
    wire();
  }
})();

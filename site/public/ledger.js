// The ledger tallies down to its final score.
//
// This lives in `public/` as a real file rather than as an inline <script> in
// the page, and that is a CSP decision, not a style one. Astro inlines a small
// module script directly into the HTML, which `script-src 'self'` blocks — the
// page would render perfectly and this animation would silently never run, with
// nothing failing except a console message nobody reads. `public/` is copied
// verbatim and served from our own origin, so the strict policy holds and the
// script still executes.
const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
const final = document.querySelector(".final");

if (final && !reduce.matches) {
  const target = Number(final.dataset.countTo ?? "48");
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        observer.disconnect();
        const start = performance.now();
        const from = 100;
        const duration = 900;
        const tick = (now) => {
          const t = Math.min((now - start) / duration, 1);
          // ease-out cubic — decelerates into the answer
          const eased = 1 - Math.pow(1 - t, 3);
          final.textContent = String(Math.round(from + (target - from) * eased));
          if (t < 1) requestAnimationFrame(tick);
          else final.textContent = String(target);
        };
        requestAnimationFrame(tick);
      }
    },
    { threshold: 0.6 },
  );
  observer.observe(final);
}

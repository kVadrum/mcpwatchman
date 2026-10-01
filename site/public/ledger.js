// The worked example subtracts itself: the kept (amber) share of the meter
// starts full and gives up each deduction in ledger order, revealing the red
// slice beneath it, while the score counts down beside it.
//
// This lives in `public/` as a real file rather than as an inline <script> in
// the page, and that is a CSP decision, not a style one. Astro inlines a small
// module script directly into the HTML, which `script-src 'self'` blocks — the
// page would render perfectly and this animation would silently never run, with
// nothing failing except a console message nobody reads. `public/` is copied
// verbatim and served from our own origin, so the strict policy holds and the
// script still executes.
//
// The markup is authored in its FINAL state, so without this script (or with
// reduced motion) the reader sees the right answer, not a frame of the motion.
const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
const final = document.querySelector(".final");
const meter = document.querySelector(".readout__meter");
const kept = meter?.querySelector(".m-scored");
// A slice's label names a deduction the bar has not yet shown, so each one
// waits for its beat; the kept figure waits for the last.
const sliceLabels = [...(meter?.querySelectorAll(".m-lost-label") ?? [])];
const keptLabel = meter?.querySelector(".m-kept-label");

if (final && meter && kept && !reduce.matches) {
  const target = Number(final.dataset.countTo ?? "48");
  const start = Number(meter.dataset.start ?? "100");
  // One beat per deduction: the balance after each, in ledger order.
  const stops = (meter.dataset.steps ?? "").split(" ").filter(Boolean).map(Number);
  const BEAT = 520;
  const PAUSE = 140;

  const show = (value) => {
    kept.setAttribute("width", `${value}%`);
    final.textContent = String(Math.round(value));
  };

  const observer = new IntersectionObserver(
    (entries) => {
      if (!entries.some((e) => e.isIntersecting)) return;
      observer.disconnect();
      for (const label of [...sliceLabels, keptLabel]) label?.classList.add("is-pending");
      show(start);
      let from = start;
      let i = 0;
      let beatStart = performance.now() + PAUSE * 2;
      const tick = (now) => {
        const t = Math.min(Math.max((now - beatStart) / BEAT, 0), 1);
        // ease-out cubic — each deduction decelerates into its new balance
        const eased = 1 - Math.pow(1 - t, 3);
        show(from + (stops[i] - from) * eased);
        if (t < 1) return requestAnimationFrame(tick);
        from = stops[i];
        sliceLabels[i]?.classList.remove("is-pending");
        i += 1;
        if (i < stops.length) {
          beatStart = now + PAUSE;
          return requestAnimationFrame(tick);
        }
        kept.setAttribute("width", `${from}%`);
        keptLabel?.classList.remove("is-pending");
        final.textContent = String(target);
      };
      requestAnimationFrame(tick);
    },
    { threshold: 0.6 },
  );
  observer.observe(meter);
}

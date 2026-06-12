/* SvgSymbolSystem — one sprite, one visual language: 24×24 viewBox,
 * 1.5px stroke, round caps/joins, fill none unless semantic.
 *
 * Standard glyphs are vendored from Lucide v1.18.0 (lucide.dev), ISC License,
 * (c) Lucide Contributors — copied as raw path data so the demo stays
 * dependency-free and offline-safe. `breaker` and `beacon` are bespoke
 * PactFuse semantics and stay hand-drawn in the same grammar. */

const SYMBOLS = `
<symbol id="sym-shield" viewBox="0 0 24 24">
  <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>
  <path d="m9 12 2 2 4-4"/>
</symbol>
<symbol id="sym-breaker" viewBox="0 0 24 24">
  <path d="M2.5 12h5"/><path d="M16.5 12h5"/>
  <circle cx="7.5" cy="12" r="1.3" fill="currentColor" stroke="none"/>
  <circle cx="16.5" cy="12" r="1.3" fill="currentColor" stroke="none"/>
  <path d="M7.5 12 15 8.2"/>
</symbol>
<symbol id="sym-deny" viewBox="0 0 24 24">
  <circle cx="12" cy="12" r="10"/>
  <path d="M4.929 4.929 19.07 19.071"/>
</symbol>
<symbol id="sym-doc" viewBox="0 0 24 24">
  <path d="M6 22a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.704.706l3.588 3.588A2.4 2.4 0 0 1 20 8v12a2 2 0 0 1-2 2z"/>
  <path d="M14 2v5a1 1 0 0 0 1 1h5"/>
  <path d="m9 15 2 2 4-4"/>
</symbol>
<symbol id="sym-play" viewBox="0 0 24 24">
  <path d="M5 5a2 2 0 0 1 3.008-1.728l11.997 6.998a2 2 0 0 1 .003 3.458l-12 7A2 2 0 0 1 5 19z"/>
</symbol>
<symbol id="sym-reset" viewBox="0 0 24 24">
  <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>
  <path d="M3 3v5h5"/>
</symbol>
<symbol id="sym-retry" viewBox="0 0 24 24">
  <path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/>
  <path d="M21 3v5h-5"/>
</symbol>
<symbol id="sym-copy" viewBox="0 0 24 24">
  <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
  <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
</symbol>
<symbol id="sym-close" viewBox="0 0 24 24">
  <path d="M18 6 6 18"/><path d="m6 6 12 12"/>
</symbol>
<symbol id="sym-check" viewBox="0 0 24 24">
  <path d="M20 6 9 17l-5-5"/>
</symbol>
<symbol id="sym-pulse" viewBox="0 0 24 24">
  <path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/>
</symbol>
`;

export function mountSymbolSprite() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("aria-hidden", "true");
  svg.style.cssText = "position:absolute;width:0;height:0;overflow:hidden";
  svg.innerHTML = `<defs>${SYMBOLS}</defs>`;
  document.body.prepend(svg);
}

export function icon(name) {
  return `<svg class="icon" aria-hidden="true"><use href="#sym-${name}"></use></svg>`;
}

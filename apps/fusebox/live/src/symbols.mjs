/* SvgSymbolSystem — one sprite, one visual language: 24×24 viewBox,
 * 1.5px stroke, round caps/joins, fill none unless semantic. Components
 * reference symbols with icon("name"); decorative uses set aria-hidden. */

const SYMBOLS = `
<symbol id="sym-bolt" viewBox="0 0 24 24">
  <path d="M13 3 6 14h5l-1 7 8-11h-5l1-7Z" stroke-linejoin="round"/>
</symbol>
<symbol id="sym-shield" viewBox="0 0 24 24">
  <path d="M12 3.5 5 6v5.5c0 4.4 3 7.7 7 9 4-1.3 7-4.6 7-9V6l-7-2.5Z" stroke-linejoin="round"/>
  <path d="m8.8 12 2.3 2.3 4.1-4.6"/>
</symbol>
<symbol id="sym-breaker" viewBox="0 0 24 24">
  <path d="M2.5 12h5"/><path d="M16.5 12h5"/>
  <circle cx="7.5" cy="12" r="1.3" fill="currentColor" stroke="none"/>
  <circle cx="16.5" cy="12" r="1.3" fill="currentColor" stroke="none"/>
  <path class="sym-breaker-arm" d="M7.5 12 15 8.2"/>
</symbol>
<symbol id="sym-beacon" viewBox="0 0 24 24">
  <path d="M12 5.2 18.8 12 12 18.8 5.2 12 12 5.2Z" stroke-linejoin="round"/>
  <circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none"/>
</symbol>
<symbol id="sym-deny" viewBox="0 0 24 24">
  <circle cx="12" cy="12" r="8.2"/>
  <path d="M6.6 6.6l10.8 10.8"/>
</symbol>
<symbol id="sym-doc" viewBox="0 0 24 24">
  <path d="M7 3.5h7l4 4v13H7v-17Z" stroke-linejoin="round"/>
  <path d="M14 3.5v4h4"/><path d="M9.5 12.5h5M9.5 16h5"/>
</symbol>
<symbol id="sym-chain" viewBox="0 0 24 24">
  <path d="M10.5 13.5a4 4 0 0 0 5.7 0l3-3a4 4 0 1 0-5.7-5.6l-1.2 1.2"/>
  <path d="M13.5 10.5a4 4 0 0 0-5.7 0l-3 3a4 4 0 1 0 5.7 5.6l1.2-1.2"/>
</symbol>
<symbol id="sym-play" viewBox="0 0 24 24">
  <path d="M8 5.5v13l11-6.5-11-6.5Z" stroke-linejoin="round"/>
</symbol>
<symbol id="sym-reset" viewBox="0 0 24 24">
  <path d="M5 12a7 7 0 1 1 2.5 5.4"/><path d="M5 17.5V12h5.5" stroke-linejoin="round"/>
</symbol>
<symbol id="sym-copy" viewBox="0 0 24 24">
  <rect x="8.5" y="8.5" width="11" height="11" rx="2"/>
  <path d="M5 14.5h-.5v-10h10V5"/>
</symbol>
<symbol id="sym-close" viewBox="0 0 24 24">
  <path d="m6.5 6.5 11 11M17.5 6.5l-11 11"/>
</symbol>
<symbol id="sym-check" viewBox="0 0 24 24">
  <path d="m5 12.5 4.5 4.5L19 7.5"/>
</symbol>
<symbol id="sym-retry" viewBox="0 0 24 24">
  <path d="M19 12a7 7 0 1 1-2.5-5.4"/><path d="M19 6.5V12h-5.5" stroke-linejoin="round"/>
</symbol>
<symbol id="sym-pulse" viewBox="0 0 24 24">
  <path d="M3 12h4l2.5-6 4 12 2.5-6H21"/>
</symbol>
`;

export function mountSymbolSprite() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("aria-hidden", "true");
  svg.style.cssText = "position:absolute;width:0;height:0;overflow:hidden";
  svg.innerHTML = `<defs>${SYMBOLS}</defs>`;
  document.body.prepend(svg);
}

export function icon(name, opts = {}) {
  const label = opts.label ? `role="img" aria-label="${opts.label}"` : 'aria-hidden="true"';
  return `<svg class="icon ${opts.cls ?? ""}" ${label}><use href="#sym-${name}"></use></svg>`;
}

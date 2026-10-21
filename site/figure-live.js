(() => {
  document.getElementById("verity-fig-stage").innerHTML = window.__VERITY_FIG_A + window.__VERITY_FIG_B;
const P = {"origin":[333.722456589712,208.1378971196951],"scale":1.48336775350287,"azimuth":42,"elevation":30};
const STOPS = [{"id":"injection","x":-45,"score":0.96,"blade":false,"text":"injection · 0.96 · BLOCKED 400 · no model"},{"id":"policy","x":-8,"score":0.12,"blade":true,"text":"policy block · 0.12 · BLOCKED 400"},{"id":"benign","x":72,"score":0.04,"blade":false,"text":"benign · 0.04 · delivered 200 · 0.21 ms"}];
const DIAL = [-85,-47];
const DIAL_R = 16, DIAL_TOP = 53;
const stage = document.getElementById("verity-fig-stage");
const svg = stage.querySelector("svg");
const carriage = svg.querySelector('[data-part="carriage"]');
const bladeG = svg.querySelector('[data-part="blade"]');
const needle = svg.querySelector('[data-part="needle"]');
const lampG = svg.querySelector('[data-part="lamp"]');
const readout = stage.closest(".iso-plate").querySelector("[data-readout]");
const still = matchMedia("(prefers-reduced-motion: reduce)");
const clamp = (value, low, high) => Math.min(high, Math.max(low, value));
const needleAt = (turn) => {
  const angle = turn * Math.PI * 2;
  const [x, y] = DIAL;
  return lineOnTop([x - Math.sin(angle) * 3.4, y + Math.cos(angle) * 3.4], [x + Math.sin(angle) * (DIAL_R - 4), y - Math.cos(angle) * (DIAL_R - 4)], DIAL_TOP + 0.2, P);
};
let idx = 0, targetIdx = 0;
let x = STOPS[0].x, bladeZ = 0;
let score = { at: STOPS[0].score, rate: 0 };
let frame = 0, last = 0, clock = 0, touring = true, visible = false, idleTimer = 0, lampOn = null, ariaIdx = -1;
const tourAt = (t) => Math.floor(t / 3) % STOPS.length;
function draw() {
  carriage.setAttribute("transform", translateAlong(P, [x, 0, 0]));
  bladeG.setAttribute("transform", translateAlong(P, [0, 0, bladeZ]));
  needle.setAttribute("d", needleAt(score.at));
  const stop = STOPS[targetIdx];
  const arrived = Math.abs(x - stop.x) < 3 && Math.abs(score.at - stop.score) < 0.02 && Math.abs(bladeZ - (stop.blade ? -28 : 0)) < 1;
  const on = targetIdx === 2 && arrived;
  if (on !== lampOn) { lampOn = on; lampG.setAttribute("opacity", on ? "1" : "0.22"); }
  const text = arrived ? stop.text : "travelling · scanner " + score.at.toFixed(2);
  if (readout.textContent !== text) readout.textContent = text;
  if (ariaIdx !== targetIdx) { ariaIdx = targetIdx; stage.setAttribute("aria-valuenow", String(targetIdx)); stage.setAttribute("aria-valuetext", stop.text); }
}
function tick(now) {
  const dt = last ? Math.min((now - last) / 1000, 1 / 30) : 1 / 60;
  last = now;
  const calm = still.matches;
  if (touring) { clock += dt; targetIdx = tourAt(clock); }
  const stop = STOPS[targetIdx];
  const target = stop.x;
  x = calm ? target : x + (target - x) * (1 - Math.exp(-dt / 0.28));
  if (Math.abs(target - x) < 0.01) x = target;
  const bladeTarget = stop.blade ? -28 : 0;
  bladeZ = calm ? bladeTarget : bladeZ + (bladeTarget - bladeZ) * (1 - Math.exp(-dt / 0.22));
  if (Math.abs(bladeTarget - bladeZ) < 0.05) bladeZ = bladeTarget;
  const stiff = 420, drag = calm ? 2 * Math.sqrt(420) : 26;
  for (let i = 0; i < 4; i++) { score.rate += ((stop.score - score.at) * stiff - score.rate * drag) * dt / 4; score.at += score.rate * dt / 4; }
  if (Math.abs(stop.score - score.at) < 0.002 && Math.abs(score.rate) < 0.002) { score.at = stop.score; score.rate = 0; }
  draw();
  const settled = !touring && x === target && bladeZ === bladeTarget && score.rate === 0 && score.at === stop.score;
  frame = visible && !settled ? requestAnimationFrame(tick) : 0;
}
const run = () => { if (!frame && visible) { last = 0; frame = requestAnimationFrame(tick); } };
const steer = (next) => { touring = false; targetIdx = clamp(next, 0, STOPS.length - 1); clearTimeout(idleTimer); idleTimer = setTimeout(() => { touring = !still.matches; clock = targetIdx * 3; run(); }, 3600); run(); };
new IntersectionObserver((entries) => { visible = entries[entries.length - 1].isIntersecting; if (visible) run(); }, { rootMargin: "120px 0px" }).observe(stage);
if (still.matches) touring = false;
stage.addEventListener("pointermove", (event) => {
  const box = svg.getBoundingClientRect();
  const share = clamp(((event.clientX - box.left) / box.width - 0.25) / 0.5, 0, 1);
  steer(Math.round(share * (STOPS.length - 1)));
});
stage.addEventListener("pointerleave", () => steer(targetIdx));
stage.addEventListener("keydown", (event) => {
  let to = null;
  if (event.key === "ArrowRight" || event.key === "ArrowUp") to = targetIdx + 1;
  if (event.key === "ArrowLeft" || event.key === "ArrowDown") to = targetIdx - 1;
  if (event.key === "Home") to = 0;
  if (event.key === "End") to = STOPS.length - 1;
  if (to === null) return;
  event.preventDefault();
  steer(to);
});
draw();

})();
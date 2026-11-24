/* Campus routing. The campus (buildings, rooms, scale) lives in data.json and is edited by guards in the
   Campus tab. The walkways below are drawn on top of public/campus-map.png, in pixels of that image.
   If you replace the image, update IMG and the WALK_NODES points. */
const IMG = { file: "/campus-map.png", width: 905, height: 834 };
const WALK_SPEED = 1.4; // meters per second

// Walkways (pixel positions on the map image). Buildings connect to the nearest walkway point.
const WALK_NODES = {
  GP: { name: "Guard Post (Main Gate)", short: "Gate", x: 592, y: 290 },
  W0: { name: "Main walkway (north)", x: 580, y: 312 },
  W1: { name: "Main walkway", x: 556, y: 368 },
  W2: { name: "Main walkway (middle)", x: 520, y: 448 },
  W3: { name: "Main walkway (south)", x: 485, y: 524 },
  W4: { name: "Main walkway (south end)", x: 462, y: 578 },
  SG: { name: "South gate", short: "South gate", x: 437, y: 628 },
  N1: { name: "Footpath (west of main walkway)", x: 520, y: 314 },
  N2: { name: "Footpath (west side)", x: 452, y: 345 },
  T1: { name: "North path", x: 650, y: 328 },
  T2: { name: "North path (east)", x: 730, y: 360 },
  T3: { name: "East path (north)", x: 785, y: 402 },
  R1: { name: "East path", x: 800, y: 505 },
  R2: { name: "East path (south)", x: 770, y: 590 },
  R3: { name: "East path (south end)", x: 748, y: 655 },
  S1: { name: "South path", x: 500, y: 634 },
  S2: { name: "South path (middle)", x: 580, y: 672 },
  S3: { name: "South path (east)", x: 660, y: 709 },
  S4: { name: "South path (far east)", x: 715, y: 730 }
};
const WALK_LINKS = [
  ["GP", "W0"], ["W0", "W1"], ["W1", "W2"], ["W2", "W3"], ["W3", "W4"], ["W4", "SG"],
  ["W0", "N1"], ["N1", "N2"],
  ["GP", "T1"], ["T1", "T2"], ["T2", "T3"], ["T3", "R1"], ["R1", "R2"], ["R2", "R3"],
  ["W4", "S1"], ["S1", "S2"], ["S2", "S3"], ["S3", "S4"], ["S4", "R3"]
];

/* ============ Default campus (used the first time the server starts) ============ */
function defaultCampus() {
  const rooms = [];
  const add = (buildingId, id, label, floor = 1) => rooms.push({ id, buildingId, label, floor });
  // A. New Building: 201-205, 301-305, 401-405, 501-505 (room ids unchanged so old history still matches)
  for (const f of [2, 3, 4, 5]) for (let n = 1; n <= 5; n++) add("NEW", `NEW-${f}0${n}`, `Room ${f}0${n}`, f);
  // B. Court
  add("COURT", "COURT-COURT", "Court");
  // C. Old Building (from the floor plans). 1st floor, listed roughly nearest-to-the-entrance first.
  for (const n of [112, 113, 114, 115, 116, 117, 118, 119, 105, 106, 107, 120, 121, 122, 101]) add("OLD", `OLD-${n}`, `Room ${n}`, 1);
  // 2nd floor
  for (let n = 1; n <= 4; n++) add("OLD", `OLD-CL${n}`, `CL${n}`, 2);
  for (let n = 5; n <= 8; n++) add("OLD", `OLD-RM${n}`, `RM${n}`, 2);
  // Rooms from the earlier map that are not in the floor plans: hidden, but kept so old history still shows their names
  for (const [id, label] of [["OLD-102", "Room 102"], ["OLD-103", "Room 103"], ["OLD-104", "Room 104"], ["OLD-110", "Room 110"], ["OLD-FUNCTION-HALL", "Function Hall"]])
    rooms.push({ id, buildingId: "OLD", label, floor: 1, archived: true });
  return {
    seed: "v3",
    mpp: 0.4, // meters per pixel of the map image (guards can change it)
    buildings: [
      { id: "NEW", name: "New Building", x: 418, y: 402 },   // A on the map
      { id: "COURT", name: "Court", x: 498, y: 430 },        // B
      { id: "OLD", name: "Old Building", x: 548, y: 440 },   // C
      { id: "D", name: "Building D", x: 808, y: 452 },
      { id: "E", name: "Building E", x: 703, y: 668 }
    ],
    rooms
  };
}

/* ============ Graph, rebuilt whenever the campus changes ============ */
const ROOMS = [];     // same array object forever; refilled by configure()
let NODES = {}, EDGE = new Map(), ADJ = new Map(), TREES = new Map(), MPP = 0.4, BUILDINGS = [];
const ekey = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`);
const ord = n => ({ 1: "1st", 2: "2nd", 3: "3rd" }[n] || `${n}th`);
const roomById = id => ROOMS.find(r => r.id === id);
const straight = (a, b) => Math.hypot(a.x - b.x, a.y - b.y) * MPP;

function link(a, b, meters, kind = "walk") {
  const w = meters ?? Math.max(1, Math.round(Math.hypot(NODES[a].x - NODES[b].x, NODES[a].y - NODES[b].y) * MPP));
  EDGE.set(ekey(a, b), { a, b, w, kind });
  for (const [p, q] of [[a, b], [b, a]]) {
    if (!ADJ.has(p)) ADJ.set(p, []);
    ADJ.get(p).push({ to: q, w });
  }
}

function configure(c) {
  MPP = c.mpp > 0 ? c.mpp : 0.4;
  BUILDINGS = c.buildings;
  NODES = {}; EDGE = new Map(); ADJ = new Map(); TREES = new Map();

  for (const [id, n] of Object.entries(WALK_NODES)) NODES[id] = { ...n, outdoor: true };
  for (const [a, b] of WALK_LINKS) link(a, b);

  ROOMS.length = 0;
  ROOMS.push({ id: "GP", building: null, buildingId: null, label: NODES.GP.name, name: NODES.GP.name, x: NODES.GP.x, y: NODES.GP.y });

  for (const b of c.buildings) {
    const mine = c.rooms.filter(r => r.buildingId === b.id);
    const live = !b.archived;
    const entrance = `B_${b.id}`;
    if (live) {
      NODES[entrance] = { name: `${b.name} entrance`, short: b.name, x: b.x, y: b.y, outdoor: true, level: 1 };
      let near = null, bd = Infinity; // nearest walkway point, like a path from the door to the road
      for (const [id, n] of Object.entries(WALK_NODES)) {
        const d = Math.hypot(n.x - b.x, n.y - b.y);
        if (d < bd) { near = id; bd = d; }
      }
      link(near, entrance, Math.max(3, Math.round(bd * MPP)), "walk");
      const top = Math.max(1, ...mine.filter(r => !r.archived).map(r => r.floor || 1));
      for (let f = 2; f <= top; f++) {
        NODES[`${entrance}_F${f}`] = { name: `${b.name} ${ord(f)} floor hallway`, x: b.x, y: b.y, level: f };
        link(f === 2 ? entrance : `${entrance}_F${f - 1}`, `${entrance}_F${f}`, f === 2 ? 20 : 14, "stairs");
      }
    }
    const seen = {}; // position along each floor's hallway
    for (const r of mine) {
      const floor = r.floor || 1, archived = !!(r.archived || b.archived);
      const room = { id: r.id, buildingId: b.id, building: b.name, label: r.label, floor, name: `${b.name} - ${r.label}`, x: b.x, y: b.y, archived };
      ROOMS.push(room);
      if (archived) continue;
      const idx = seen[floor] = (seen[floor] ?? -1) + 1;
      NODES[r.id] = { name: room.name, x: b.x, y: b.y, room: true };
      link(floor === 1 ? entrance : `${entrance}_F${floor}`, r.id, Math.min(60, 6 + 3 * idx), "hall");
    }
  }
}

/* ============ Shortest path (Dijkstra, the same idea Google Maps uses) ============ */
const PENALTY = 2.5; // used only to look for an alternative route

function dijkstra(src, penalty) {
  const dist = new Map([[src, 0]]);
  const prev = new Map();
  const done = new Set();
  for (;;) {
    let u = null, best = Infinity;
    for (const [n, d] of dist) if (!done.has(n) && d < best) { u = n; best = d; }
    if (u === null) break;
    done.add(u);
    for (const e of ADJ.get(u) || []) {
      const cost = best + e.w * (penalty && penalty.has(ekey(u, e.to)) ? PENALTY : 1);
      if (cost < (dist.get(e.to) ?? Infinity)) { dist.set(e.to, cost); prev.set(e.to, u); }
    }
  }
  return { dist, prev };
}

const tree = src => { if (!TREES.has(src)) TREES.set(src, dijkstra(src)); return TREES.get(src); };

function pathNodes(prev, src, dst) {
  const out = [dst];
  while (out[0] !== src) {
    const p = prev.get(out[0]);
    if (p === undefined) return null;
    out.unshift(p);
  }
  return out;
}

// Real walking distance in meters between two points (falls back to a straight line if not on the map)
function walkMeters(a, b) {
  const t = tree(a);
  if (t.dist.has(b)) return t.dist.get(b);
  const A = roomById(a), B = roomById(b);
  return A && B ? straight(A, B) : 0;
}

function pack(nodes) {
  let meters = 0;
  const steps = [];
  for (let i = 1; i < nodes.length; i++) {
    const e = EDGE.get(ekey(nodes[i - 1], nodes[i]));
    const to = NODES[nodes[i]];
    meters += e.w;
    let text;
    if (e.kind === "stairs") text = `Take the stairs ${to.level > NODES[nodes[i - 1]].level ? "up" : "down"} to ${to.name}`;
    else if (e.kind === "hall") text = `Walk along the hallway to ${to.name}`;
    else text = `Walk to ${to.name}`;
    steps.push({ text, meters: e.w });
  }
  const via = nodes.slice(1, -1).filter(n => NODES[n].outdoor).map(n => NODES[n].name);
  return { meters, seconds: meters / WALK_SPEED, nodes, steps, via };
}

function describeRoute(fromId, toId) {
  const t = tree(fromId);
  const nodes = t.dist.has(toId) ? pathNodes(t.prev, fromId, toId) : null;
  if (!nodes) {
    const A = roomById(fromId), B = roomById(toId);
    const m = A && B ? straight(A, B) : 0;
    return { meters: m, seconds: m / WALK_SPEED, nodes: [], steps: m ? [{ text: `Go to ${B ? B.name : toId}`, meters: m }] : [], via: [], alt: null };
  }
  const best = pack(nodes);

  let alt = null;
  if (nodes.length > 1) {
    const used = new Set();
    for (let i = 1; i < nodes.length; i++) used.add(ekey(nodes[i - 1], nodes[i]));
    const p = dijkstra(fromId, used);
    const other = p.dist.has(toId) ? pathNodes(p.prev, fromId, toId) : null;
    if (other && other.join() !== nodes.join()) {
      const packed = pack(other);
      if (packed.meters <= best.meters * 1.6) alt = packed;
    }
  }
  return { ...best, alt };
}

/**
 * Order the pending requests: nearest first by real walking distance (weight 0 = no first-come-first-served).
 * Equal distances go to the request that has waited longer.
 */
function buildSchedule(pending, startRoom, agingWeight, now = Date.now()) {
  const route = [];
  let current = startRoom;
  let elapsed = 0;
  let left = [...pending];

  while (left.length) {
    let best = null;
    for (const r of left) {
      const d = walkMeters(current.id, r.roomId);
      const waitMin = (now - new Date(r.createdAt)) / 60000;
      const cost = d - agingWeight * waitMin;
      const older = best && Date.parse(r.createdAt) < Date.parse(best.req.createdAt);
      if (!best || cost < best.cost || (cost === best.cost && older)) best = { req: r, leg: d, cost };
    }
    elapsed += best.leg / WALK_SPEED;
    route.push({ req: best.req, leg: best.leg, eta: elapsed, from: current.id });
    current = roomById(best.req.roomId) || { id: best.req.roomId };
    left = left.filter(x => x.id !== best.req.id);
  }
  return route;
}

function routeLength(order, startRoom) {
  let cur = startRoom.id, total = 0;
  for (const r of order) { total += walkMeters(cur, r.roomId); cur = r.roomId; }
  return total;
}

// A room, or any outdoor walkway point (used when the start follows the guard's live location)
const startPoint = id => (roomById(id) ? roomById(id) : NODES[id] && NODES[id].outdoor ? { id } : null);

// What the pages need to draw the campus map
function mapData() {
  const coords = Object.fromEntries(Object.entries(NODES).map(([id, n]) => [id, [n.x, n.y]]));
  const nodes = Object.entries(NODES).filter(([, n]) => n.short).map(([id, n]) => ({ id, short: n.short, x: n.x, y: n.y }));
  const edges = [...EDGE.values()].filter(e => NODES[e.a].outdoor && NODES[e.b].outdoor).map(e => [e.a, e.b]);
  const outdoor = Object.entries(NODES).filter(([, n]) => n.outdoor).map(([id, n]) => ({ id, x: n.x, y: n.y }));
  return { image: IMG.file, width: IMG.width, height: IMG.height, mpp: MPP, coords, nodes, edges, outdoor };
}

module.exports = { ROOMS, roomById, startPoint, defaultCampus, configure, buildSchedule, describeRoute, routeLength, mapData };

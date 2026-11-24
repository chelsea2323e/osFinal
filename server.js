require("dotenv").config();
const fs = require("fs");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");
const db = require("./db");
const { ROOMS, roomById, startPoint, defaultCampus, configure, buildSchedule, describeRoute, routeLength, mapData } = require("./scheduler");

// Campus (buildings, rooms, map scale) is stored in data.json and edited by guards.
// A campus made from an older default that no guard has edited yet is replaced by the current default.
if (!db.data.campus || (!db.data.campus.edited && db.data.campus.seed !== defaultCampus().seed)) { db.data.campus = defaultCampus(); db.save(); }
configure(db.data.campus);

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
if (!process.env.JWT_SECRET) {
  console.warn("JWT_SECRET is not set. Using a temporary secret; everyone is signed out on restart.");
}

const ROLES = ["Professor", "Guard"]; // roles guards can create (Student removed)
const DOMAIN = (process.env.ALLOWED_EMAIL_DOMAIN || "cvsu.edu.ph").toLowerCase();
// Guards may use any email address; students and professors need the school domain.
const emailAllowed = (e, role) => role === "Guard" || e.split("@").pop() === DOMAIN;

const app = express();
const smallJson = express.json({ limit: "10kb" });
app.use((req, res, next) => (req.path.endsWith("/proof") ? next() : smallJson(req, res, next)));
app.use(express.static(path.join(__dirname, "public")));

const fail = (res, code, msg) => res.status(code).json({ error: msg });
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  message: { error: "Too many attempts. Try again in a few minutes." }
});

/* ---------- Password helpers ---------- */
const pwOk = pw =>
  pw.length >= 8 && /[A-Z]/.test(pw) && /[a-z]/.test(pw) && /[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw);
const PW_MSG = "Password needs 8+ characters, an uppercase and a lowercase letter, a number and a special character.";

function makeTempPassword() {
  const pick = s => s[crypto.randomInt(s.length)];
  const U = "ABCDEFGHJKLMNPQRSTUVWXYZ", L = "abcdefghijkmnopqrstuvwxyz", N = "23456789", S = "!@#$%&*?";
  const chars = [pick(U), pick(L), pick(N), pick(S)];
  while (chars.length < 12) chars.push(pick(U + L + N + S));
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

/* ---------- Seed the built-in guard account ---------- */
// Runs on every start but only creates the account when no guard exists yet.
function seedGuard() {
  let changed = false;
  for (const u of db.data.users) if (u.role === "Admin") { u.role = "Guard"; changed = true; } // older data
  if (!db.data.users.some(u => u.role === "Guard")) {
    const email = (process.env.GUARD_EMAIL || "guard@cvsu.edu.ph").trim().toLowerCase();
    const password = process.env.GUARD_PASSWORD || "Guard@12345";
    const existing = db.data.users.find(u => u.email === email);
    if (existing) {
      existing.role = "Guard";
    } else {
      db.data.users.push({
        id: crypto.randomUUID(),
        email,
        role: "Guard",
        name: "Main Guard",
        passwordHash: bcrypt.hashSync(password, 10),
        // The built-in default password must be changed at first sign-in.
        tempPassword: !process.env.GUARD_PASSWORD,
        createdAt: new Date().toISOString()
      });
    }
    changed = true;
    console.log(`Built-in guard account ready: ${email}` + (process.env.GUARD_PASSWORD ? "" : " (default password: Guard@12345, change it after signing in)"));
  }
  if (changed) db.save();
}
seedGuard();

/* ---------- Auth helpers ---------- */
const session = u => ({
  token: jwt.sign({ id: u.id }, SECRET, { expiresIn: "8h" }),
  user: { email: u.email, role: u.role, name: u.name, tempPassword: !!u.tempPassword },
});

// The account is looked up on every request, so deleted accounts and role changes apply immediately.
// Users on a temporary password can only reach the routes that use authTemp.
const authWith = allowTemp => (req, res, next) => {
  const h = req.headers.authorization || "";
  let payload;
  try {
    payload = jwt.verify(h.startsWith("Bearer ") ? h.slice(7) : "", SECRET);
  } catch {
    return fail(res, 401, "Please sign in again.");
  }
  const u = db.data.users.find(x => x.id === payload.id);
  if (!u) return fail(res, 401, "Please sign in again.");
  if (u.tempPassword && !allowTemp) return fail(res, 403, "Change your temporary password first.");
  req.user = { id: u.id, email: u.email, role: u.role, name: u.name };
  next();
};
const auth = authWith(false);
const authTemp = authWith(true);

const only = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : fail(res, 403, "Not allowed for your role.");

const pub = ({ requesterId, proofFile, ...rest }) => ({ ...rest, hasProof: !!proofFile });
const pubUser = u => ({
  id: u.id, name: u.name, email: u.email, role: u.role, createdAt: u.createdAt, mustChange: !!u.tempPassword
});

/* ---------- Auth routes ---------- */
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", 10);

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const { email = "", password = "", role = "" } = req.body || {};
  const user = db.data.users.find(u => u.email === String(email).trim().toLowerCase());
  // Same work and same message whether or not the email exists, so emails can't be probed.
  const match = await bcrypt.compare(String(password), user ? user.passwordHash : DUMMY_HASH);
  if (!user || !match || user.role !== role) return fail(res, 401, "Incorrect email, password or role.");
  res.json(session(user));
});

app.post("/api/me/password", authLimiter, authTemp, async (req, res) => {
  const { current = "", next = "" } = req.body || {};
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!(await bcrypt.compare(String(current), u.passwordHash))) return fail(res, 401, "Current password is incorrect.");
  if (!pwOk(String(next))) return fail(res, 400, PW_MSG);
  if (String(next) === String(current)) return fail(res, 400, "Choose a password different from the current one.");
  u.passwordHash = await bcrypt.hash(String(next), 10);
  u.tempPassword = false;
  db.save();
  res.json({ ok: true });
});

app.post("/api/me/email", authLimiter, auth, async (req, res) => {
  const { email = "", password = "" } = req.body || {};
  const u = db.data.users.find(x => x.id === req.user.id);
  if (u.role === "Professor") return fail(res, 403, "Professors cannot change their email address.");
  const e = String(email).trim().toLowerCase();
  if (!(await bcrypt.compare(String(password), u.passwordHash))) return fail(res, 401, "Password is incorrect.");
  if (!/^\S+@\S+\.\S+$/.test(e)) return fail(res, 400, "Enter a valid email address.");
  if (e === u.email) return fail(res, 400, "That is already your email address.");
  if (!emailAllowed(e, u.role)) return fail(res, 400, `Use an @${DOMAIN} email address.`);
  if (db.data.users.some(x => x.email === e)) return fail(res, 409, "That email is already registered.");
  const old = u.email;
  u.email = e;
  // Requests keep the email as a label, so carry them over to the new address.
  for (const r of db.data.requests) {
    for (const k of ["requester", "handledBy", "completedBy"]) if (r[k] === old) r[k] = e;
  }
  db.save();
  res.json({ email: e });
});

app.post("/api/me/mobile", auth, (req, res) => {
  const num = String((req.body || {}).mobile ?? "").trim().replace(/[\s\-().]/g, "");
  if (num && !/^\+?\d{10,15}$/.test(num)) {
    return fail(res, 400, "Enter a valid mobile number, e.g. 09171234567 or +639171234567.");
  }
  const u = db.data.users.find(x => x.id === req.user.id);
  u.mobile = num; // an empty value removes it
  db.save();
  res.json({ mobile: num });
});

/* ---------- Account management ---------- */
// Only guards can list, create, reset and delete accounts.
app.get("/api/accounts", auth, only("Guard"), (req, res) => {
  res.json(db.data.users.map(pubUser).sort((a, b) => a.role.localeCompare(b.role) || a.email.localeCompare(b.email)));
});

app.post("/api/accounts", auth, only("Guard"), async (req, res) => {
  const { email = "", role = "", name = "" } = req.body || {};
  const e = String(email).trim().toLowerCase();
  const fullName = String(name).trim().slice(0, 60);

  if (!fullName) return fail(res, 400, "Enter the full name.");
  if (!/^\S+@\S+\.\S+$/.test(e)) return fail(res, 400, "Enter a valid email address.");
  if (!ROLES.includes(role)) return fail(res, 400, "Choose a valid role.");
  if (!emailAllowed(e, role)) return fail(res, 400, `Use an @${DOMAIN} email address for this role.`);
  if (db.data.users.some(u => u.email === e)) return fail(res, 409, "That email is already registered.");

  const temp = makeTempPassword();
  const user = {
    id: crypto.randomUUID(),
    email: e,
    role,
    name: fullName,
    passwordHash: await bcrypt.hash(temp, 10),
    tempPassword: true,
    createdAt: new Date().toISOString(),
    createdBy: req.user.email
  };
  db.data.users.push(user);
  db.save();
  res.status(201).json({ name: user.name, email: user.email, role: user.role, tempPassword: temp });
});

app.post("/api/accounts/:id/reset", auth, only("Guard"), async (req, res) => {
  const u = db.data.users.find(x => x.id === req.params.id);
  if (!u) return fail(res, 404, "Account not found.");
  if (u.id === req.user.id) return fail(res, 400, "Use Change password for your own account.");
  const temp = makeTempPassword();
  u.passwordHash = await bcrypt.hash(temp, 10);
  u.tempPassword = true;
  db.save();
  res.json({ name: u.name, email: u.email, tempPassword: temp });
});

app.delete("/api/accounts/:id", auth, only("Guard"), (req, res) => {
  const u = db.data.users.find(x => x.id === req.params.id);
  if (!u) return fail(res, 404, "Account not found.");
  if (u.id === req.user.id) return fail(res, 400, "You cannot delete your own account.");
  if (u.role === "Guard" && db.data.users.filter(x => x.role === "Guard").length <= 1) {
    return fail(res, 400, "You cannot delete the last guard account.");
  }
  db.data.users = db.data.users.filter(x => x.id !== u.id);
  db.save();
  res.json({ ok: true });
});

/* ---------- Rooms ---------- */
app.get("/api/rooms", authTemp, (req, res) => res.json(ROOMS));

// Campus walkway map the guard's route screen draws
app.get("/api/map", auth, only("Guard"), (req, res) => res.json(mapData()));

/* ---------- Campus editor (guards): buildings, rooms, map scale ---------- */
const cleanName = (v, max = 40) => String(v ?? "").replace(/\s+/g, " ").trim().slice(0, max);
const slug = s => s.toUpperCase().replace(/[^A-Z0-9]+/g, "-").replace(/^-+|-+$/g, "");
const sameName = (a, b) => a.toLowerCase() === b.toLowerCase();
const commitCampus = () => { db.data.campus.edited = true; db.save(); configure(db.data.campus); };
// A room can't be removed while someone is waiting for it or has it booked
const roomInUse = id => db.data.requests.some(r => r.roomId === id && (r.status === "pending" || holdsRoom(r)));
const findBuilding = id => db.data.campus.buildings.find(b => b.id === id && !b.archived);
const findRoom = id => db.data.campus.rooms.find(r => r.id === id && !r.archived);
const mapPoint = (x, y) => {
  const m = mapData();
  return Number.isFinite(x) && Number.isFinite(y) && x >= 0 && y >= 0 && x <= m.width && y <= m.height;
};
const parseFloor = v => { const f = Math.round(Number(v ?? 1)); return f >= 1 && f <= 15 ? f : null; };

app.get("/api/campus", auth, only("Guard"), (req, res) => {
  const c = db.data.campus;
  res.json({
    mpp: c.mpp,
    buildings: c.buildings.filter(b => !b.archived),
    rooms: c.rooms.filter(r => !r.archived && findBuilding(r.buildingId)).map(r => ({ ...r, inUse: roomInUse(r.id) })),
    map: mapData()
  });
});

app.post("/api/campus/buildings", auth, only("Guard"), (req, res) => {
  const c = db.data.campus, name = cleanName(req.body && req.body.name);
  if (!name) return fail(res, 400, "Enter a building name.");
  if (c.buildings.filter(b => !b.archived).length >= 30) return fail(res, 400, "That is the maximum number of buildings.");
  if (c.buildings.some(b => !b.archived && sameName(b.name, name))) return fail(res, 409, "A building with that name already exists.");
  // building ids have no "-" so room ids (BUILDING-ROOM) can never clash with them
  const base = slug(name).replace(/-/g, "") || "BLDG";
  let id = base, n = 2;
  while (c.buildings.some(b => b.id === id) || id === "GP") id = `${base}${n++}`;
  const m = mapData();
  const made = { id, name, x: Math.round(m.width / 2), y: Math.round(m.height / 2) };
  c.buildings.push(made);
  commitCampus();
  res.status(201).json(made);
});

app.patch("/api/campus/buildings/:id", auth, only("Guard"), (req, res) => {
  const c = db.data.campus, b = findBuilding(req.params.id);
  if (!b) return fail(res, 404, "Building not found.");
  const { name, x, y } = req.body || {};
  if (name !== undefined) {
    const nm = cleanName(name);
    if (!nm) return fail(res, 400, "Enter a building name.");
    if (c.buildings.some(o => o !== b && !o.archived && sameName(o.name, nm))) return fail(res, 409, "A building with that name already exists.");
    b.name = nm;
  }
  if (x !== undefined || y !== undefined) {
    if (!mapPoint(Number(x), Number(y))) return fail(res, 400, "Pick a spot inside the map.");
    b.x = Math.round(Number(x)); b.y = Math.round(Number(y));
  }
  commitCampus();
  res.json(b);
});

app.delete("/api/campus/buildings/:id", auth, only("Guard"), (req, res) => {
  const c = db.data.campus, b = findBuilding(req.params.id);
  if (!b) return fail(res, 404, "Building not found.");
  const mine = c.rooms.filter(r => r.buildingId === b.id && !r.archived);
  if (mine.some(r => roomInUse(r.id))) return fail(res, 409, "A room in this building has a pending or booked request. Finish or deny it first.");
  b.archived = true;                       // kept (hidden) so old history still shows its name
  mine.forEach(r => { r.archived = true; });
  commitCampus();
  res.json({ ok: true });
});

app.post("/api/campus/rooms", auth, only("Guard"), (req, res) => {
  const c = db.data.campus, b = findBuilding(req.body && req.body.buildingId);
  if (!b) return fail(res, 404, "Choose a building.");
  const floor = parseFloor(req.body.floor);
  if (!floor) return fail(res, 400, "Floor must be a number from 1 to 15.");
  const labels = String(req.body.labels ?? req.body.label ?? "").split(/[,\n]/).map(x => cleanName(x, 30)).filter(Boolean);
  if (!labels.length) return fail(res, 400, "Enter at least one room name.");
  if (labels.length > 60) return fail(res, 400, "Add up to 60 rooms at a time.");
  if (c.rooms.filter(r => !r.archived).length + labels.length > 500) return fail(res, 400, "That would be too many rooms.");
  const added = [], skipped = [];
  for (const label of labels) {
    if (c.rooms.some(r => !r.archived && r.buildingId === b.id && sameName(r.label, label))) { skipped.push(label); continue; }
    const base = `${b.id}-${slug(label) || "ROOM"}`;
    let id = base, n = 2;
    while (c.rooms.some(r => r.id === id)) id = `${base}-${n++}`;
    const room = { id, buildingId: b.id, label, floor };
    c.rooms.push(room); added.push(room);
  }
  if (added.length) commitCampus();
  res.status(added.length ? 201 : 200).json({ added, skipped });
});

app.patch("/api/campus/rooms/:id", auth, only("Guard"), (req, res) => {
  const c = db.data.campus, r = findRoom(req.params.id);
  if (!r) return fail(res, 404, "Room not found.");
  const { label, floor } = req.body || {};
  if (label !== undefined) {
    const lb = cleanName(label, 30);
    if (!lb) return fail(res, 400, "Enter a room name.");
    if (c.rooms.some(o => o !== r && !o.archived && o.buildingId === r.buildingId && sameName(o.label, lb))) return fail(res, 409, "That building already has a room with this name.");
    r.label = lb;
  }
  if (floor !== undefined) {
    const f = parseFloor(floor);
    if (!f) return fail(res, 400, "Floor must be a number from 1 to 15.");
    r.floor = f;
  }
  commitCampus();
  res.json(r);
});

app.delete("/api/campus/rooms/:id", auth, only("Guard"), (req, res) => {
  const r = findRoom(req.params.id);
  if (!r) return fail(res, 404, "Room not found.");
  if (roomInUse(r.id)) return fail(res, 409, "This room has a pending or booked request. Finish or deny it first.");
  r.archived = true;                       // kept (hidden) so old history still shows its name
  commitCampus();
  res.json({ ok: true });
});

app.patch("/api/campus/settings", auth, only("Guard"), (req, res) => {
  const mpp = Number(req.body && req.body.mpp);
  if (!(mpp >= 0.05 && mpp <= 5)) return fail(res, 400, "Meters per pixel must be between 0.05 and 5.");
  db.data.campus.mpp = mpp;
  commitCampus();
  res.json({ mpp });
});


/* ---------- Room time slots ---------- */
// A request books its room from startAt to endAt. Once a guard approves it, the room is held for that
// window; when the window ends the room is free again (see releaseEnded below).
const DURATIONS = [30, 60, 90, 120, 150, 180, 240, 300, 360, 480]; // minutes a room can be requested for
const slotOf = r => (r.startAt && r.endAt) ? { s: Date.parse(r.startAt), e: Date.parse(r.endAt) } : null;
const clash = (a, b) => !!(a && b && a.s < b.e && b.s < a.e);
const holdsRoom = r => (r.status === "approved" || r.status === "completed") && slotOf(r) && slotOf(r).e > Date.now();
const bookedClash = (roomId, slot, ignoreId) =>
  db.data.requests.find(r => r.id !== ignoreId && r.roomId === roomId && holdsRoom(r) && clash(slotOf(r), slot));

function autoDeny(r, why) {
  r.status = "denied";
  r.denyReason = why;
  r.handledBy = "system";
  r.handledAt = new Date().toISOString();
}

// Times (no names) when a room is already taken, so requesters can pick a free slot
app.get("/api/rooms/:id/busy", auth, (req, res) => {
  if (!roomById(req.params.id)) return fail(res, 404, "Room not found.");
  res.json(
    db.data.requests
      .filter(r => r.roomId === req.params.id && holdsRoom(r))
      .map(r => ({ startAt: r.startAt, endAt: r.endAt }))
      .sort((a, b) => Date.parse(a.startAt) - Date.parse(b.startAt))
  );
});

/* ---------- Requests: Student / Professor ---------- */
app.post("/api/requests", auth, only("Student", "Professor"), (req, res) => {
  const { roomId, neededAt, startAt, durationMin, reason = "" } = req.body || {};
  const text = String(reason).trim();

  const chosen = roomById(roomId);
  if (!chosen || chosen.archived || roomId === "GP") return fail(res, 400, "Choose a classroom.");
  if (!text || text.length > 300) return fail(res, 400, "Add a reason (up to 300 characters).");

  // Time slot: when the room is needed and for how long (defaults: now, 1 hour)
  const dur = durationMin === undefined ? 60 : Number(durationMin);
  if (!DURATIONS.includes(dur)) return fail(res, 400, "Choose how long you need the room.");
  const start = startAt === undefined ? Date.now() : Date.parse(startAt);
  if (Number.isNaN(start)) return fail(res, 400, "Choose a valid start time.");
  if (start < Date.now() - 5 * 60 * 1000) return fail(res, 400, "That start time has already passed. Pick a later time.");
  if (start > Date.now() + 24 * 60 * 60 * 1000) return fail(res, 400, "That start time is too far ahead.");
  const slot = { s: start, e: start + dur * 60 * 1000 };
  if (bookedClash(roomId, slot)) {
    return fail(res, 409, "This room is already booked at that time. Pick another time, a shorter duration or another room.");
  }

  const open = db.data.requests.filter(r => r.requesterId === req.user.id && r.status === "pending");
  if (open.length >= 5) return fail(res, 429, "You already have 5 pending requests.");

  const request = {
    id: crypto.randomUUID(),
    requesterId: req.user.id,
    requester: req.user.email,
    role: req.user.role,
    roomId,
    neededAt: String(neededAt || "").slice(0, 20) || "As soon as possible",
    startAt: new Date(slot.s).toISOString(),
    endAt: new Date(slot.e).toISOString(),
    durationMin: dur,
    reason: text,
    status: "pending",
    createdAt: new Date().toISOString()
  };
  db.data.requests.push(request);
  db.save();
  res.status(201).json(pub(request));
});

const startOfToday = () => { const d = new Date(); d.setHours(0, 0, 0, 0); return d; };

app.get("/api/requests/mine", auth, only("Student", "Professor"), (req, res) => {
  const wantHistory = req.query.scope === "history";
  const cutoff = startOfToday();
  res.json(
    db.data.requests
      .filter(r => r.requesterId === req.user.id && (new Date(r.createdAt) >= cutoff) !== wantHistory)
      .reverse()
      .slice(0, 100)
      .map(pub)
  );
});

// Pending requests from earlier days can no longer be acted on, so mark them expired
function expireOld() {
  const cutoff = startOfToday();
  let changed = false;
  for (const r of db.data.requests) {
    if (r.status === "pending" && (new Date(r.createdAt) < cutoff || (r.endAt && Date.parse(r.endAt) <= Date.now()))) {
      r.status = "expired";
      r.expiredAt = new Date().toISOString();
      changed = true;
    }
  }
  if (changed) db.save();
}
expireOld();                        // on startup
setInterval(expireOld, 60 * 1000);  // every minute, so midnight is caught

// When an approved/completed booking's time is up, record that the room is free again.
// The guard's history shows this, and bookedClash() stops counting the booking.
function releaseEnded() {
  const now = Date.now();
  let changed = false;
  for (const r of db.data.requests) {
    if ((r.status === "approved" || r.status === "completed") && r.endAt && !r.releasedAt && Date.parse(r.endAt) <= now) {
      r.releasedAt = new Date().toISOString();
      changed = true;
    }
  }
  if (changed) db.save();
}
releaseEnded();
setInterval(releaseEnded, 30 * 1000);

/* ---------- Guard: schedule, history, decisions ---------- */
app.get("/api/schedule", auth, only("Guard"), (req, res) => {
  const start = startPoint(req.query.start) || roomById("GP");
  const weight = 0; // pure nearest-first by real walking distance (no first-come-first-served, no aging)
  const pending = db.data.requests.filter(r => r.status === "pending");
  const ordered = buildSchedule(pending, start, weight);
  const route = ordered.map(s => ({
    request: pub(s.req),
    leg: s.leg,                                        // walking meters from the previous stop
    eta: s.eta,
    directions: describeRoute(s.from, s.req.roomId)    // shortest route, steps and an alternative
  }));
  // Compare with answering requests in the order they arrived
  const fcfs = [...pending].sort((x, y) => Date.parse(x.createdAt) - Date.parse(y.createdAt));
  res.json({
    route,
    stats: {
      totalMeters: Math.round(ordered.reduce((n, s) => n + s.leg, 0)),
      fcfsMeters: Math.round(routeLength(fcfs, start))
    }
  });
});

app.get("/api/requests/history", auth, only("Guard"), (req, res) => {
  expireOld();
  releaseEnded();
  const cutoff = startOfToday();
  const earlier = req.query.scope === "earlier";
  res.json(
    db.data.requests
      .filter(r => r.status !== "pending" && (new Date(r.createdAt) < cutoff) === earlier)
      .reverse()
      .slice(0, 100)
      .map(pub)
  );
});

// Every approved or completed request (rooms actually granted), newest first. Feeds the History categories.
app.get("/api/usage", auth, only("Guard"), (req, res) => {
  const names = new Map(db.data.users.map(u => [u.id, u.name]));
  res.json(
    db.data.requests
      .filter(r => r.status === "approved" || r.status === "completed")
      .map(r => ({ ...pub(r), requesterName: names.get(r.requesterId) || "" }))
      .reverse()
  );
});

const NEXT = { pending: ["approved", "denied"] };

app.patch("/api/requests/:id", auth, only("Guard"), (req, res) => {
  const request = db.data.requests.find(r => r.id === req.params.id);
  if (!request) return fail(res, 404, "Request not found.");

  const status = (req.body || {}).status;
  if (!(NEXT[request.status] || []).includes(status)) {
    return fail(res, 409, `A ${request.status} request cannot become ${status}.`);
  }
  if (status === "denied") {
    const why = String((req.body || {}).reason || "").trim();
    if (!why) return fail(res, 400, "Please give a reason for denying this request.");
    if (why.length > 300) return fail(res, 400, "The reason must be 300 characters or fewer.");
    request.denyReason = why;
  }
  if (status === "approved") {
    const slot = slotOf(request);
    if (slot && bookedClash(request.roomId, slot, request.id)) {
      autoDeny(request, "The room is already in use at that time.");
      db.save();
      return fail(res, 409, "That room is already booked at that time, so this request was denied automatically.");
    }
    if (slot && slot.e <= Date.now()) {
      request.status = "expired";
      request.expiredAt = new Date().toISOString();
      db.save();
      return fail(res, 409, "The time for this request has already ended, so it was expired.");
    }
    // Anyone else waiting for the same room at an overlapping time loses out automatically
    for (const o of db.data.requests) {
      if (o.id !== request.id && o.status === "pending" && o.roomId === request.roomId && clash(slotOf(o), slot)) {
        autoDeny(o, "Another request was approved for this room at the same time.");
      }
    }
  }
  request.status = status;
  request.handledBy = req.user.email;
  request.handledAt = new Date().toISOString();
  db.save();
  res.json(pub(request));
});

/* ---------- Proof photos ---------- */
const PROOF_DIR = path.join(db.DIR, "uploads"); // follows DATA_DIR so photos persist too
fs.mkdirSync(PROOF_DIR, { recursive: true });

// Guard completes an approved request by uploading a photo
app.post("/api/requests/:id/proof", auth, only("Guard"), express.json({ limit: "2mb" }), (req, res) => {
  const request = db.data.requests.find(r => r.id === req.params.id);
  if (!request) return fail(res, 404, "Request not found.");
  if (request.status !== "approved") return fail(res, 409, "Only approved requests can be completed.");

  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec((req.body || {}).image || "");
  if (!m) return fail(res, 400, "Upload a JPEG photo.");
  const buf = Buffer.from(m[1], "base64");
  const isJpeg = buf[0] === 0xff && buf[1] === 0xd8;
  if (!isJpeg || buf.length < 1000 || buf.length > 1.5 * 1024 * 1024) {
    return fail(res, 400, "That photo is not valid or is too large.");
  }

  const file = `${request.id}.jpg`;
  fs.writeFileSync(path.join(PROOF_DIR, file), buf);
  request.proofFile = file;
  request.status = "completed";
  request.completedBy = req.user.email;
  request.completedAt = new Date().toISOString();
  db.save();
  res.json(pub(request));
});

// Only guards and the person who made the request can view the photo
app.get("/api/requests/:id/proof", auth, (req, res) => {
  const r = db.data.requests.find(x => x.id === req.params.id);
  if (!r || !r.proofFile) return fail(res, 404, "No proof photo.");
  if (req.user.role !== "Guard" && r.requesterId !== req.user.id) return fail(res, 403, "Not allowed.");
  res.type("image/jpeg").sendFile(path.join(PROOF_DIR, r.proofFile));
});

/* ---------- Profile ---------- */
app.get("/api/me", authTemp, (req, res) => {
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!u) return fail(res, 404, "Account not found.");
  const mine = u.role === "Guard"
    ? db.data.requests.filter(r => r.handledBy === u.email)
    : db.data.requests.filter(r => r.requesterId === u.id);
  const count = s => mine.filter(r => r.status === s).length;
  res.json({
    name: u.name, email: u.email, role: u.role, createdAt: u.createdAt, total: mine.length,
    tempPassword: !!u.tempPassword, mobile: u.mobile || "",
    approved: count("approved"), completed: count("completed"),
    denied: count("denied"), expired: count("expired")
  });
});

/* ---------- Fallbacks ---------- */
app.use("/api", (req, res) => fail(res, 404, "Unknown endpoint."));
app.use((err, req, res, next) => {
  console.error(err);
  fail(res, err.status || 500, err.status ? "Invalid request." : "Something went wrong.");
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running at http://localhost:${PORT}`);
  // Addresses other devices on the same Wi-Fi/network can use (phone, tablet, another laptop)
  const nets = require("os").networkInterfaces();
  for (const list of Object.values(nets)) {
    for (const n of list || []) {
      if (n.family === "IPv4" && !n.internal) console.log(`On your phone (same Wi-Fi): http://${n.address}:${PORT}`);
    }
  }
});

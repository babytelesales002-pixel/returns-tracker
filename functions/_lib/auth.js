// Shared auth helpers for Pages Functions

const SESSION_COOKIE = 'session';
const SESSION_DAYS = 30;

export function genId(prefix = '') {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return prefix + hex;
}

export function slugifyUsername(s) {
  return String(s || '').trim().toLowerCase()
    .replace(/[^a-z0-9ก-๙_\-.~]/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 100) || 'user';
}

async function pbkdf2Hash(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const salt = saltHex
    ? new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)))
    : crypto.getRandomValues(new Uint8Array(16));
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const hashHex = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  const saltOut = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  return { saltHex: saltOut, hashHex };
}

export async function hashPassword(password) {
  const { saltHex, hashHex } = await pbkdf2Hash(password);
  return `${saltHex}:${hashHex}`;
}

export async function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [saltHex, expectedHash] = stored.split(':');
  const { hashHex } = await pbkdf2Hash(password, saltHex);
  return hashHex === expectedHash;
}

function parseCookies(req) {
  const header = req.headers.get('Cookie') || '';
  const out = {};
  header.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i === -1) return;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

export function sessionCookieHeader(token, maxAgeSeconds) {
  const parts = [
    `${SESSION_COOKIE}=${token}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ];
  return parts.join('; ');
}

export function clearSessionCookieHeader() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export async function createSession(db, userId) {
  const token = genId('sess_');
  const expires = new Date(Date.now() + SESSION_DAYS * 86400 * 1000).toISOString();
  await db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(token, userId, expires).run();
  return { token, maxAgeSeconds: SESSION_DAYS * 86400 };
}

export async function getSessionUser(request, db) {
  const cookies = parseCookies(request);
  const token = cookies[SESSION_COOKIE];
  if (!token) return null;
  const session = await db.prepare('SELECT * FROM sessions WHERE token = ?').bind(token).first();
  if (!session) return null;
  if (new Date(session.expires_at).getTime() < Date.now()) {
    await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }
  const user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(session.user_id).first();
  return user || null;
}

export function json(data, init = {}) {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init.headers || {}) },
  });
}

export function toUserDto(u) {
  if (!u) return null;
  return { id: u.id, name: u.name, username: u.username, role: u.role, team: u.team };
}

export function toReturnDto(r) {
  return {
    id: r.id, date: r.date, parcel: r.parcel, carrier: r.carrier, phone: r.phone,
    product: r.product, customer: r.customer, address: r.address,
    subdistrict: r.subdistrict, district: r.district, province: r.province, zip: r.zip,
    seller: r.seller, team: r.team, price: r.price, orderQty: r.order_qty, returnQty: r.return_qty,
    reasonCat: r.reason_cat, reasonNote: r.reason_note,
  };
}

import { getSessionUser, genId, slugifyUsername, hashPassword, json, toUserDto } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me) return json({ error: 'unauthorized' }, { status: 401 });
  // any signed-in user can see the roster (names/roles/teams only, no password hashes)
  const { results } = await db.prepare('SELECT * FROM users ORDER BY created_at ASC').all();
  return json({ users: results.map(toUserDto) });
}

export async function onRequestPost({ request, env }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me || me.role !== 'admin') return json({ error: 'forbidden' }, { status: 403 });

  const body = await request.json().catch(() => ({}));
  const name = String(body.name || '').trim();
  const usernameRaw = String(body.username || '').trim();
  const password = String(body.password || '');
  const role = ['admin', 'viewer_all', 'print_view', 'lead', 'sales'].includes(body.role) ? body.role : 'sales';
  const team = String(body.team || '');

  if (!name || !usernameRaw || password.length < 4) {
    return json({ error: 'invalid_input' }, { status: 400 });
  }
  const username = slugifyUsername(usernameRaw);
  const existing = await db.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) return json({ error: 'username_taken' }, { status: 409 });

  const id = genId('u_');
  const passwordHash = await hashPassword(password);
  await db.prepare(
    'INSERT INTO users (id, name, username, password_hash, role, team) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(id, name, username, passwordHash, role, team).run();

  return json({ user: { id, name, username, role, team } }, { status: 201 });
}

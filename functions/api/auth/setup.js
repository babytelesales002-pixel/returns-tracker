import { genId, slugifyUsername, hashPassword, createSession, sessionCookieHeader, json, toUserDto } from '../../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const db = env.DB;
  const countRow = await db.prepare('SELECT COUNT(*) AS c FROM users').first();
  if (countRow.c > 0) {
    return json({ error: 'already_setup' }, { status: 409 });
  }

  const body = await request.json().catch(() => ({}));
  const name = String(body.name || '').trim();
  const usernameRaw = String(body.username || '').trim();
  const password = String(body.password || '');
  if (!name || !usernameRaw || password.length < 4) {
    return json({ error: 'invalid_input' }, { status: 400 });
  }

  const id = genId('u_');
  const username = slugifyUsername(usernameRaw);
  const passwordHash = await hashPassword(password);

  await db.prepare(
    'INSERT INTO users (id, name, username, password_hash, role, team) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(id, name, username, passwordHash, 'admin', '').run();

  const { token, maxAgeSeconds } = await createSession(db, id);
  const user = { id, name, username, role: 'admin', team: '' };
  return json({ user }, { headers: { 'Set-Cookie': sessionCookieHeader(token, maxAgeSeconds) } });
}

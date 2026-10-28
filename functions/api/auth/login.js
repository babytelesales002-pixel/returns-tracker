import { slugifyUsername, verifyPassword, createSession, sessionCookieHeader, json, toUserDto } from '../../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const db = env.DB;
  const body = await request.json().catch(() => ({}));
  const usernameRaw = String(body.username || '').trim();
  const password = String(body.password || '');
  if (!usernameRaw || !password) {
    return json({ error: 'invalid_input' }, { status: 400 });
  }
  const username = slugifyUsername(usernameRaw);
  const user = await db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  if (!user) return json({ error: 'not_found' }, { status: 404 });

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return json({ error: 'wrong_password' }, { status: 401 });

  const { token, maxAgeSeconds } = await createSession(db, user.id);
  return json({ user: toUserDto(user) }, { headers: { 'Set-Cookie': sessionCookieHeader(token, maxAgeSeconds) } });
}

import { getSessionUser, verifyPassword, hashPassword, json } from '../../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me) return json({ error: 'unauthorized' }, { status: 401 });

  const body = await request.json().catch(() => ({}));
  const oldPassword = String(body.oldPassword || '');
  const newPassword = String(body.newPassword || '');
  if (!oldPassword || newPassword.length < 4) {
    return json({ error: 'invalid_input' }, { status: 400 });
  }

  const ok = await verifyPassword(oldPassword, me.password_hash);
  if (!ok) return json({ error: 'wrong_password' }, { status: 401 });

  const newHash = await hashPassword(newPassword);
  await db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(newHash, me.id).run();

  return json({ ok: true });
}

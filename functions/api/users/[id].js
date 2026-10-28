import { getSessionUser, hashPassword, json } from '../../_lib/auth.js';

export async function onRequestDelete({ request, env, params }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me || me.role !== 'admin') return json({ error: 'forbidden' }, { status: 403 });
  if (params.id === me.id) return json({ error: 'cannot_delete_self' }, { status: 400 });
  await db.prepare('DELETE FROM users WHERE id = ?').bind(params.id).run();
  await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(params.id).run();
  return json({ ok: true });
}

// admin resets another user's password (no need to know their old password)
export async function onRequestPatch({ request, env, params }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me || me.role !== 'admin') return json({ error: 'forbidden' }, { status: 403 });

  const body = await request.json().catch(() => ({}));
  const newPassword = String(body.newPassword || '');
  if (newPassword.length < 4) return json({ error: 'invalid_input' }, { status: 400 });

  const target = await db.prepare('SELECT id FROM users WHERE id = ?').bind(params.id).first();
  if (!target) return json({ error: 'not_found' }, { status: 404 });

  const newHash = await hashPassword(newPassword);
  await db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(newHash, params.id).run();
  await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(params.id).run();
  return json({ ok: true });
}

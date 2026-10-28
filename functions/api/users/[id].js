import { getSessionUser, json } from '../../_lib/auth.js';

export async function onRequestDelete({ request, env, params }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me || me.role !== 'admin') return json({ error: 'forbidden' }, { status: 403 });
  if (params.id === me.id) return json({ error: 'cannot_delete_self' }, { status: 400 });
  await db.prepare('DELETE FROM users WHERE id = ?').bind(params.id).run();
  await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(params.id).run();
  return json({ ok: true });
}

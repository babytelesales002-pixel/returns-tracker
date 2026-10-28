import { getSessionUser, json } from '../../_lib/auth.js';

export async function onRequestDelete({ request, env, params }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me || me.role !== 'admin') return json({ error: 'forbidden' }, { status: 403 });
  await db.prepare('DELETE FROM teams WHERE id = ?').bind(params.id).run();
  return json({ ok: true });
}

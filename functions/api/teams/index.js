import { getSessionUser, genId, json } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me) return json({ error: 'unauthorized' }, { status: 401 });
  const { results } = await db.prepare('SELECT * FROM teams ORDER BY created_at ASC').all();
  return json({ teams: results.map(t => ({ id: t.id, name: t.name })) });
}

export async function onRequestPost({ request, env }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me || me.role !== 'admin') return json({ error: 'forbidden' }, { status: 403 });
  const body = await request.json().catch(() => ({}));
  const name = String(body.name || '').trim();
  if (!name) return json({ error: 'invalid_input' }, { status: 400 });
  const id = genId('t_');
  await db.prepare('INSERT INTO teams (id, name) VALUES (?, ?)').bind(id, name).run();
  return json({ team: { id, name } }, { status: 201 });
}

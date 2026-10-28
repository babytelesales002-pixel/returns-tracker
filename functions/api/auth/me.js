import { getSessionUser, json, toUserDto } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const db = env.DB;
  const user = await getSessionUser(request, db);
  const countRow = await db.prepare('SELECT COUNT(*) AS c FROM users').first();
  return json({ user: toUserDto(user), needsSetup: countRow.c === 0 });
}

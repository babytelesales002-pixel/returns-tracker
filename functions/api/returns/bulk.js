import { getSessionUser, genId, json } from '../../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me || me.role !== 'admin') return json({ error: 'forbidden' }, { status: 403 });

  const body = await request.json().catch(() => ({}));
  const rows = Array.isArray(body.rows) ? body.rows : [];
  if (!rows.length) return json({ error: 'invalid_input' }, { status: 400 });

  const stmt = db.prepare(`INSERT INTO returns
    (id, date, parcel, carrier, phone, product, customer, address, subdistrict, district, province, zip, seller, team, price, order_qty, return_qty, reason_cat, reason_note, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`);

  const batch = rows.map(b => stmt.bind(
    genId('r_'), b.date || '', b.parcel || '', b.carrier || '', b.phone || '', b.product || '',
    b.customer || '', b.address || '', b.subdistrict || '', b.district || '', b.province || '',
    b.zip || '', b.seller || '', b.team || '', Number(b.price) || 0, Number(b.orderQty) || 0,
    Number(b.returnQty) || 0, b.reasonCat || '', b.reasonNote || ''
  ));

  // D1 batch caps around 100 statements per call; chunk to be safe
  for (let i = 0; i < batch.length; i += 90) {
    await db.batch(batch.slice(i, i + 90));
  }

  return json({ added: rows.length });
}

export async function onRequestDelete({ request, env }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me) return json({ error: 'unauthorized' }, { status: 401 });

  const canAll = me.role === 'admin' || me.role === 'viewer_all';
  if (me.role !== 'admin' && !canAll) {
    // only admin may actually delete, but keep message consistent
  }
  if (me.role !== 'admin') return json({ error: 'forbidden' }, { status: 403 });

  const url = new URL(request.url);
  const scopeTeam = url.searchParams.get('team');
  if (scopeTeam) {
    await db.prepare('DELETE FROM returns WHERE team = ?').bind(scopeTeam).run();
  } else {
    await db.prepare('DELETE FROM returns').run();
  }
  return json({ ok: true });
}

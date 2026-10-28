import { getSessionUser, genId, json, toReturnDto } from '../../_lib/auth.js';

function canSeeAll(user) {
  return user.role === 'admin' || user.role === 'viewer_all' || user.role === 'print_view';
}

export async function onRequestGet({ request, env }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me) return json({ error: 'unauthorized' }, { status: 401 });

  let rows;
  if (canSeeAll(me)) {
    rows = (await db.prepare('SELECT * FROM returns ORDER BY date DESC').all()).results;
  } else {
    rows = (await db.prepare('SELECT * FROM returns WHERE team = ? ORDER BY date DESC').bind(me.team || '').all()).results;
  }
  return json({ returns: rows.map(toReturnDto) });
}

export async function onRequestPost({ request, env }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me || me.role !== 'admin') return json({ error: 'forbidden' }, { status: 403 });

  const b = await request.json().catch(() => ({}));
  if (!b.date || !b.product) return json({ error: 'invalid_input' }, { status: 400 });

  const id = genId('r_');
  await db.prepare(`INSERT INTO returns
    (id, date, parcel, carrier, phone, product, customer, address, subdistrict, district, province, zip, seller, team, price, order_qty, return_qty, reason_cat, reason_note, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
    .bind(
      id, b.date || '', b.parcel || '', b.carrier || '', b.phone || '', b.product || '',
      b.customer || '', b.address || '', b.subdistrict || '', b.district || '', b.province || '',
      b.zip || '', b.seller || '', b.team || '', Number(b.price) || 0, Number(b.orderQty) || 0,
      Number(b.returnQty) || 0, b.reasonCat || '', b.reasonNote || ''
    ).run();

  return json({ id }, { status: 201 });
}

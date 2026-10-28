import { getSessionUser, json } from '../../_lib/auth.js';

export async function onRequestPut({ request, env, params }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me || me.role !== 'admin') return json({ error: 'forbidden' }, { status: 403 });

  const b = await request.json().catch(() => ({}));
  if (!b.date || !b.product) return json({ error: 'invalid_input' }, { status: 400 });

  await db.prepare(`UPDATE returns SET
      date=?, parcel=?, carrier=?, phone=?, product=?, customer=?, address=?, subdistrict=?,
      district=?, province=?, zip=?, seller=?, team=?, price=?, order_qty=?, return_qty=?,
      reason_cat=?, reason_note=?, updated_at=datetime('now')
    WHERE id=?`)
    .bind(
      b.date || '', b.parcel || '', b.carrier || '', b.phone || '', b.product || '',
      b.customer || '', b.address || '', b.subdistrict || '', b.district || '', b.province || '',
      b.zip || '', b.seller || '', b.team || '', Number(b.price) || 0, Number(b.orderQty) || 0,
      Number(b.returnQty) || 0, b.reasonCat || '', b.reasonNote || '', params.id
    ).run();

  return json({ ok: true });
}

export async function onRequestDelete({ request, env, params }) {
  const db = env.DB;
  const me = await getSessionUser(request, db);
  if (!me || me.role !== 'admin') return json({ error: 'forbidden' }, { status: 403 });
  await db.prepare('DELETE FROM returns WHERE id = ?').bind(params.id).run();
  return json({ ok: true });
}

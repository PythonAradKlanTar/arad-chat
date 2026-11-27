import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' };
Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...cors, 'Content-Type': 'application/json' } });
  try {
    const url = Deno.env.get('SUPABASE_URL')!, anon = Deno.env.get('SUPABASE_ANON_KEY')!, service = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const authHeader = req.headers.get('Authorization'); if (!authHeader) return json({ error: 'Unauthorized' }, 401);
    const userClient = createClient(url, anon, { global: { headers: { Authorization: authHeader } } });
    const { data: { user }, error: authError } = await userClient.auth.getUser();
    if (authError || !user) return json({ error: 'Unauthorized' }, 401);
    const admin = createClient(url, service);
    const { data: staff } = await admin.from('staff_roles').select('role').eq('user_id', user.id).maybeSingle();
    if (!staff || !['owner', 'admin'].includes(staff.role)) return json({ error: 'Forbidden' }, 403);
    const body = await req.json(); const { action, target_user_id, reason, days } = body;
    if (!target_user_id || target_user_id === user.id) return json({ error: 'Invalid target user' }, 400);
    if (staff.role !== 'owner' && ['ban_temp','ban_permanent','unban','verify_grant','verify_revoke','premium_grant','premium_revoke'].includes(action)) return json({ error: 'Owner permission required' }, 403);
    const valid = ['ban_temp','ban_permanent','unban','verify_grant','verify_revoke','premium_grant','premium_revoke'];
    if (!valid.includes(action)) return json({ error: 'Unknown action' }, 400);
    let expires_at: string | null = null;
    if (action === 'ban_temp') { const n = Number(days); if (![1,3,10,15,30,90,100].includes(n)) return json({ error: 'Invalid ban duration' }, 400); expires_at = new Date(Date.now() + n * 86400000).toISOString(); }
    if (action === 'ban_temp' || action === 'ban_permanent') {
      const banDuration = action === 'ban_permanent' ? '876000h' : `${Number(days) * 24}h`;
      const { error: authBanError } = await admin.auth.admin.updateUserById(target_user_id, { ban_duration: banDuration }); if (authBanError) throw authBanError;
      const { error } = await admin.from('user_bans').insert({ user_id: target_user_id, issued_by: user.id, reason: String(reason || 'بدون توضیح').slice(0,1000), expires_at }); if (error) throw error;
    } else if (action === 'unban') {
      const { error: authUnbanError } = await admin.auth.admin.updateUserById(target_user_id, { ban_duration: 'none' }); if (authUnbanError) throw authUnbanError;
      const { error } = await admin.from('user_bans').delete().eq('user_id', target_user_id); if (error) throw error;
    } else {
      const { data: old } = await admin.from('user_entitlements').select('user_id').eq('user_id', target_user_id).maybeSingle();
      const values = { user_id: target_user_id, is_verified: action === 'verify_grant' ? true : action === 'verify_revoke' ? false : undefined, is_premium: action === 'premium_grant' ? true : action === 'premium_revoke' ? false : undefined, granted_by: user.id, updated_at: new Date().toISOString() };
      const patch = Object.fromEntries(Object.entries(values).filter(([,v]) => v !== undefined));
      const { error } = old ? await admin.from('user_entitlements').update(patch).eq('user_id', target_user_id) : await admin.from('user_entitlements').insert(patch);
      if (error) throw error;
    }
    await admin.from('admin_user_actions').insert({ target_user_id, actor_id: user.id, action, reason: String(reason || '').slice(0,1000), expires_at });
    await admin.from('admin_audit_logs').insert({ actor_id: user.id, action, target_user_id, details: { reason: reason || null, days: days || null } });
    return json({ ok: true, action, target_user_id, expires_at });
  } catch (e) { return json({ error: e?.message || 'Server error' }, 500); }
});

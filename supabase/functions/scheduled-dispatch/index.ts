import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { corsHeaders } from '../_shared/cors.ts';
Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  const secret = Deno.env.get('SCHEDULER_SECRET');
  if (!secret || req.headers.get('x-scheduler-secret') !== secret) return new Response('Unauthorized', { status: 401, headers: corsHeaders });
  const url = Deno.env.get('SUPABASE_URL')!, key = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  const db = createClient(url, key);
  const { data: due, error } = await db.from('scheduled_messages').select('*').is('sent_at', null).lte('send_at', new Date().toISOString()).order('send_at').limit(100);
  if (error) return Response.json({ error: error.message }, { status: 500, headers: corsHeaders });
  let sent = 0, skipped = 0;
  for (const item of due || []) {
    const { data: member } = await db.from('conversation_members').select('user_id').eq('conversation_id', item.conversation_id).eq('user_id', item.sender_id).maybeSingle();
    if (member) {
      const { error: insertError } = await db.from('messages').insert({ conversation_id: item.conversation_id, sender_id: item.sender_id, body: item.body });
      if (insertError) continue;
      sent++;
    } else skipped++;
    await db.from('scheduled_messages').update({ sent_at: new Date().toISOString() }).eq('id', item.id).is('sent_at', null);
  }
  return Response.json({ sent, skipped, checked: due?.length || 0 }, { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
});

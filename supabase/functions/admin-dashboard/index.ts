import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' };
Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{...cors,'Content-Type':'application/json'}});
  try {
    const url=Deno.env.get('SUPABASE_URL')!, anon=Deno.env.get('SUPABASE_ANON_KEY')!, service=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const authorization=req.headers.get('Authorization'); if(!authorization)return json({error:'Unauthorized'},401);
    const userClient=createClient(url,anon,{global:{headers:{Authorization:authorization}}});
    const {data:{user},error:authError}=await userClient.auth.getUser(); if(authError||!user)return json({error:'Unauthorized'},401);
    const admin=createClient(url,service);
    const {data:staff}=await admin.from('staff_roles').select('role').eq('user_id',user.id).maybeSingle();
    if(!staff||!['owner','admin'].includes(staff.role))return json({error:'Forbidden'},403);
    const [users,messages,groups,channels,files,reports,admins]=await Promise.all([
      admin.from('profiles').select('id',{count:'exact',head:true}),
      admin.from('messages').select('id',{count:'exact',head:true}),
      admin.from('conversations').select('id',{count:'exact',head:true}).eq('kind','group'),
      admin.from('conversations').select('id',{count:'exact',head:true}).eq('kind','channel'),
      admin.from('file_asset_metadata').select('byte_size',{count:'exact'}),
      admin.from('reports').select('id,reporter_id,target_user_id,target_conversation_id,reason,status,created_at').eq('status','open').order('created_at',{ascending:false}).limit(30),
      admin.from('staff_roles').select('user_id,role,created_at').order('created_at',{ascending:false}).limit(100)
    ]);
    const bytes=(files.data||[]).reduce((n,x)=>n+Number(x.byte_size||0),0);
    return json({stats:{users:users.count||0,messages:messages.count||0,groups:groups.count||0,channels:channels.count||0,file_records:files.count||0,file_bytes:bytes},reports:reports.data||[],staff:staff.role==='owner'?(admins.data||[]):[],role:staff.role});
  } catch(e) { return json({error:e?.message||'Server error'},500); }
});

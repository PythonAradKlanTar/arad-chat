import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { corsHeaders } from '../_shared/cors.ts';
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{...corsHeaders,'Content-Type':'application/json'}});
Deno.serve(async(req)=>{
 if(req.method==='OPTIONS') return new Response('ok',{headers:corsHeaders});
 try {
  const auth=req.headers.get('Authorization'); if(!auth) return json({error:'Unauthorized'},401);
  const url=Deno.env.get('SUPABASE_URL')!, anon=Deno.env.get('SUPABASE_ANON_KEY')!, service=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  const userClient=createClient(url,anon,{global:{headers:{Authorization:auth}}});
  const {data:{user},error:ue}=await userClient.auth.getUser(); if(ue||!user) return json({error:'Unauthorized'},401);
  const db=createClient(url,service);
  const {data:staff}=await db.from('staff_roles').select('role').eq('user_id',user.id).maybeSingle();
  if(!staff) return json({error:'Forbidden'},403);
  const body=await req.json(); const op=String(body.op||''); const isOwner=staff.role==='owner';
  const ownerOnly=['set_role','delete_user','set_setting','create_invite','revoke_invite','send_broadcast','review_bot'];
  if(ownerOnly.includes(op)&&!isOwner) return json({error:'Owner permission required'},403);
  let result:any=null;
  switch(op){
   case 'list_staff': { const {data,error}=await db.from('staff_roles').select('user_id,role,granted_by,created_at').order('created_at',{ascending:false}); if(error) throw error; result=data; break; }
   case 'list_users': {
    const page=Math.max(1,Number(body.page||1)), per=Math.min(50,Math.max(1,Number(body.per_page||25)));
    const {data,error}=await db.auth.admin.listUsers({page,perPage:per}); if(error) throw error;
    result=(data.users||[]).map(u=>({id:u.id,email:u.email,created_at:u.created_at,last_sign_in_at:u.last_sign_in_at,email_confirmed_at:u.email_confirmed_at})); break;
   }
   case 'set_role': {
    const uid=String(body.user_id||''), role=String(body.role||''); if(!uid||!['admin','moderator'].includes(role)) throw new Error('Invalid user_id or role');
    const {error}=await db.from('staff_roles').upsert({user_id:uid,role,granted_by:user.id}); if(error) throw error;
    result={ok:true}; break;
   }
   case 'remove_role': { if(!body.user_id) throw new Error('user_id required'); const {error}=await db.from('staff_roles').delete().eq('user_id',body.user_id).neq('role','owner'); if(error) throw error; result={ok:true}; break; }
   case 'delete_user': {
    if(!isOwner) return json({error:'Owner permission required'},403);
    const uid=String(body.user_id||'');
    if(!uid||uid===user.id||body.confirmation!=='DELETE USER') throw new Error('Confirmation required; cannot delete self');
    const {data:target,error:te}=await db.from('staff_roles').select('role').eq('user_id',uid).maybeSingle();
    if(te) throw te;
    if(target?.role==='owner') throw new Error('Owner account cannot be deleted from this panel');
    const {error:ae}=await db.from('admin_audit_logs').insert({actor_id:user.id,action:'admin_console:delete_user',details:{target_user_id:uid}});
    if(ae) throw ae;
    const {error}=await db.auth.admin.deleteUser(uid);
    if(error) throw error;
    result={ok:true};
    break;
   }
   case 'list_groups': { const {data,error}=await db.from('conversations').select('id,kind,title,description,created_by,created_at').in('kind',['group','channel']).order('created_at',{ascending:false}).limit(100); if(error) throw error; result=data; break; }
   case 'group_action': { if(staff.role==='moderator') return json({error:'Admin permission required'},403); const {data:conv,error:ce}=await db.from('conversations').select('id,created_by').eq('id',body.conversation_id).maybeSingle(); if(ce||!conv) throw new Error('Conversation not found'); const uid=String(body.user_id||''); if(!uid) throw new Error('user_id required'); if(body.action==='add'){const {error}=await db.from('conversation_members').upsert({conversation_id:conv.id,user_id:uid,role:'member'});if(error)throw error;} else if(body.action==='remove'){if(uid===conv.created_by)throw new Error('Cannot remove conversation creator');const {error}=await db.from('conversation_members').delete().eq('conversation_id',conv.id).eq('user_id',uid);if(error)throw error;} else if(body.action==='rename'){const {error}=await db.from('conversations').update({title:String(body.title||'').slice(0,100),description:String(body.description||'').slice(0,2000)}).eq('id',conv.id);if(error)throw error;} else if(body.action==='promote'||body.action==='demote'){const {error}=await db.from('conversation_members').update({role:body.action==='promote'?'admin':'member'}).eq('conversation_id',conv.id).eq('user_id',uid);if(error)throw error;} else throw new Error('Unsupported group action'); await db.from('admin_group_actions').insert({conversation_id:conv.id,actor_id:user.id,action:body.action,details:{user_id:uid}}); result={ok:true}; break; }
   case 'list_bots': { const {data,error}=await db.from('bots').select('id,owner_id,username,display_name,is_active,created_at').order('created_at',{ascending:false}).limit(100); if(error) throw error; result=data; break; }
   case 'list_bot_listings': { const {data,error}=await db.from('bot_store_listings').select('id,bot_id,status,category,submitted_by,created_at').order('created_at',{ascending:false}).limit(100); if(error) throw error; result=data; break; }
   case 'review_bot': { const {error}=await db.from('bot_store_listings').update({status:body.status,reviewed_by:user.id,reviewed_at:new Date().toISOString()}).eq('id',body.id); if(error) throw error; result={ok:true}; break; }
   case 'list_reports': { const {data,error}=await db.from('reports').select('*').order('created_at',{ascending:false}).limit(100); if(error) throw error; result=data; break; }
   case 'update_report': { const {error}=await db.from('reports').update({status:body.status}).eq('id',body.id); if(error) throw error; result={ok:true}; break; }
   case 'create_invite': { const code=String(body.code||crypto.randomUUID().replaceAll('-','').slice(0,10)).toUpperCase(); const {data,error}=await db.from('invite_codes').insert({code,created_by:user.id,max_uses:Math.max(1,Number(body.max_uses||1)),expires_at:body.expires_at||null}).select().single(); if(error) throw error; result=data; break; }
   case 'list_invites': { const {data,error}=await db.from('invite_codes').select('*').order('created_at',{ascending:false}).limit(100); if(error) throw error; result=data; break; }
   case 'revoke_invite': { const {error}=await db.from('invite_codes').delete().eq('code',body.code); if(error) throw error; result={ok:true}; break; }
   case 'send_broadcast': {
    const title=String(body.title||'اطلاعیه ARAD CHAT'), message=String(body.message||''); if(!message.trim()) throw new Error('Message required');
    const {data:users,error}=await db.from('profiles').select('id'); if(error) throw error;
    const rows=(users||[]).map(x=>({user_id:x.id,title,body:message}));
    for(let i=0;i<rows.length;i+=500){const {error:e}=await db.from('notifications').insert(rows.slice(i,i+500));if(e) throw e;}
    const {error:e}=await db.from('admin_announcements').insert({created_by:user.id,title,body:message,audience:'all',status:'sent',sent_at:new Date().toISOString()}); if(e) throw e;
    result={delivered_records:rows.length}; break;
   }
   case 'stats': {
    const tables=['profiles','messages','conversations','file_asset_metadata','bots','reports']; const counts:any={};
    for(const t of tables){const {count,error}=await db.from(t).select('*',{count:'exact',head:true}); if(error) throw error; counts[t]=count||0;}
    const {data:files}=await db.from('file_asset_metadata').select('byte_size'); counts.storage_bytes=(files||[]).reduce((a,x)=>a+Number(x.byte_size||0),0); result=counts; break;
   }
   case 'audit': { const {data,error}=await db.from('admin_audit_logs').select('*').order('created_at',{ascending:false}).limit(100); if(error) throw error; result=data; break; }
   case 'get_settings': { const {data,error}=await db.from('admin_settings').select('*').order('key'); if(error) throw error; result=data; break; }
   case 'set_setting': { const {error}=await db.from('admin_settings').upsert({key:String(body.key),value:body.value,updated_by:user.id,updated_at:new Date().toISOString()}); if(error) throw error; result={ok:true}; break; }
   default: return json({error:'Unknown operation'},400);
  }
  await db.from('admin_audit_logs').insert({actor_id:user.id,action:`admin_console:${op}`,details:{op,meta:body.audit_meta||{}}});
  return json({data:result});
 } catch(e) { return json({error:e instanceof Error?e.message:String(e)},400); }
});

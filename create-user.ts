// =====================================================================
// ProdLine OS — Edge Function: create-user
// =====================================================================
// 
// الغرض: تمكين المدير العام (MGMT) من إنشاء مستخدمين جدد من داخل النظام
// يقوم بـ:
//   1. التحقق من أن الطالب مدير (MGMT)
//   2. إنشاء حساب في auth.users
//   3. ربطه بصف في public.users
//   4. تسجيل العملية في audit log
//
// =====================================================================
// خطوات النشر (بدون CLI، عبر Dashboard فقط):
// =====================================================================
// 
// 1. افتح Supabase Dashboard → مشروعك
// 
// 2. القائمة اليسرى → Edge Functions
// 
// 3. اضغط "Deploy a new function" (أو Create a new function)
// 
// 4. الاسم: create-user (مهم جداً — حرفياً نفس الاسم)
// 
// 5. اختر "Via Editor" (محرر الكود في المتصفح)
// 
// 6. الصق كل محتوى هذا الملف من السطر "import { serve }" حتى نهاية الملف
//    (أي الكود فقط، بدون التعليقات في الأعلى)
// 
// 7. اضغط "Deploy function"
// 
// 8. ⚠️ مهم: بعد النشر، لا تحتاج إعداد environment variables
//    Supabase يضع SUPABASE_URL و SUPABASE_SERVICE_ROLE_KEY تلقائياً
// 
// 9. اختبار سريع: في Dashboard → Edge Functions → create-user
//    يجب يظهر "Status: Active"
// 
// =====================================================================
// كيف يستدعيها التطبيق:
// =====================================================================
// 
// POST https://<project-ref>.supabase.co/functions/v1/create-user
// Headers:
//   Authorization: Bearer <user-jwt-token>
//   Content-Type: application/json
// Body:
//   {
//     "id": "U-100",
//     "email": "newuser@veridos.iq",
//     "password": "TempPass@2025",
//     "name_ar": "اسم بالعربي",
//     "name_en": "Name in English",
//     "dept_id": "PROD",
//     "role_ar": "مشغل K1",
//     "role_en": "K1 Operator",
//     "color": "#0ea5e9",
//     "avatar": "ع"
//   }
// 
// Response (success):
//   { "ok": true, "user_id": "U-100", "auth_uuid": "...", "message": "..." }
// 
// Response (error):
//   { "error": "وصف الخطأ" }
// 
// =====================================================================

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.39.0'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  if (req.method !== 'POST') {
    return new Response(
      JSON.stringify({ error: 'Only POST allowed' }),
      { status: 405, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  }

  try {
    // Verify caller's auth token
    const authHeader = req.headers.get('Authorization')
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(
        JSON.stringify({ error: 'يلزم تسجيل الدخول / Auth required' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Service-role admin client
    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
      { auth: { persistSession: false, autoRefreshToken: false } }
    )

    // Validate JWT and get caller
    const jwt = authHeader.replace('Bearer ', '')
    const { data: { user: caller }, error: authError } = await supabaseAdmin.auth.getUser(jwt)
    if (authError || !caller) {
      return new Response(
        JSON.stringify({ error: 'صلاحية غير صالحة / Invalid auth: ' + (authError?.message || 'no user') }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Verify caller is MGMT
    const { data: callerProfile, error: profErr } = await supabaseAdmin
      .from('users')
      .select('id, dept_id, name_ar')
      .eq('auth_user_id', caller.id)
      .single()

    if (profErr || !callerProfile) {
      return new Response(
        JSON.stringify({ error: 'لا يوجد ملف مستخدم مرتبط / Profile missing' }),
        { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    if (callerProfile.dept_id !== 'MGMT') {
      return new Response(
        JSON.stringify({ error: 'هذه العملية تتطلب صلاحية المدير العام / Manager (MGMT) required' }),
        { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Parse and validate request body
    const body = await req.json()
    const required = ['id', 'email', 'password', 'name_ar', 'name_en', 'dept_id']
    for (const f of required) {
      if (!body[f] || typeof body[f] !== 'string' || !body[f].trim()) {
        return new Response(
          JSON.stringify({ error: `الحقل مطلوب: ${f}` }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )
      }
    }

    if (body.password.length < 8) {
      return new Response(
        JSON.stringify({ error: 'كلمة السر يجب أن تكون 8 أحرف على الأقل' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    if (!/^U-\d+$/.test(body.id)) {
      return new Response(
        JSON.stringify({ error: 'صيغة المعرف غير صحيحة (مثال: U-100)' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Check user_id uniqueness
    const { data: existingId } = await supabaseAdmin
      .from('users')
      .select('id')
      .eq('id', body.id)
      .maybeSingle()
    if (existingId) {
      return new Response(
        JSON.stringify({ error: `المعرف ${body.id} موجود مسبقاً` }),
        { status: 409, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Verify dept_id exists
    const { data: dept } = await supabaseAdmin
      .from('departments')
      .select('id')
      .eq('id', body.dept_id)
      .maybeSingle()
    if (!dept) {
      return new Response(
        JSON.stringify({ error: `القسم ${body.dept_id} غير موجود` }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Create auth user (with email already confirmed)
    const { data: newAuth, error: createErr } = await supabaseAdmin.auth.admin.createUser({
      email: body.email,
      password: body.password,
      email_confirm: true,
      user_metadata: { prodline_user_id: body.id }
    })

    if (createErr || !newAuth?.user) {
      const msg = createErr?.message || 'unknown'
      const arMsg = msg.includes('already registered') 
        ? 'الإيميل مستخدم مسبقاً'
        : `فشل إنشاء حساب Auth: ${msg}`
      return new Response(
        JSON.stringify({ error: arMsg }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Insert into public.users
    const { error: insertErr } = await supabaseAdmin
      .from('users')
      .insert({
        id: body.id,
        auth_user_id: newAuth.user.id,
        name_ar: body.name_ar,
        name_en: body.name_en,
        dept_id: body.dept_id,
        role_ar: body.role_ar || null,
        role_en: body.role_en || null,
        color: body.color || '#888',
        avatar: body.avatar || body.name_ar.charAt(0),
        active: true
      })

    if (insertErr) {
      // Rollback: delete the auth user since linking failed
      await supabaseAdmin.auth.admin.deleteUser(newAuth.user.id)
      return new Response(
        JSON.stringify({ error: 'فشل ربط المستخدم: ' + insertErr.message }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Log to audit
    await supabaseAdmin
      .from('audit')
      .insert({
        user_id: callerProfile.id,
        user_name: callerProfile.name_ar,
        action: 'create_user',
        entity: 'User',
        entity_id: body.id,
        details: { email: body.email, dept: body.dept_id, via: 'edge-function' }
      })

    return new Response(
      JSON.stringify({
        ok: true,
        user_id: body.id,
        auth_uuid: newAuth.user.id,
        message: `تم إنشاء المستخدم ${body.name_ar} بنجاح`
      }),
      { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )

  } catch (e) {
    return new Response(
      JSON.stringify({ error: 'خطأ غير متوقع: ' + (e instanceof Error ? e.message : String(e)) }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  }
})

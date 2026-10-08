import { Router } from 'express';

export const apiRouter = Router();

apiRouter.get('/health', (req, res) => {
  res.json({ ok: true });
});

apiRouter.get('/config', (req, res) => {
  const supabaseUrl = process.env.SUPABASE_URL;
  const publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!supabaseUrl || !publishableKey) {
    return res.status(503).json({ ok: false, error: 'Autenticación no configurada' });
  }
  return res.json({ supabaseUrl, publishableKey });
});

async function resolveEffectivePermissions(client, roleCode) {
  return client
    .from('role_permissions')
    .select('permission_code, permissions!role_permissions_permission_code_fkey(code)')
    .eq('role_code', roleCode)
    .order('permission_code');
}

// Validates only an authenticated user's own active profile for invitation and
// recovery flows. Operational access remains guarded by /auth/profile below.
apiRouter.get('/auth/credential-profile', async (req, res) => {
  const supabaseAdmin = req.app.locals.supabaseAdmin;
  const authorization = req.get('authorization') || '';
  const token = authorization.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!supabaseAdmin || !token) {
    return res.status(401).json({ ok: false, error: 'Sesión no válida' });
  }

  try {
    const { data: authData, error: authError } = await supabaseAdmin.auth.getUser(token);
    if (authError || !authData.user) {
      return res.status(401).json({ ok: false, error: 'Sesión no válida' });
    }

    const { data: profile, error: profileError } = await supabaseAdmin
      .from('profiles')
      .select('id, first_name, last_name, role_code, is_active')
      .eq('id', authData.user.id)
      .maybeSingle();

    if (profileError) {
      console.error('No se pudo validar el perfil para configurar credenciales.');
      return res.status(503).json({ ok: false, error: 'No se pudo validar el perfil' });
    }
    if (!profile || !profile.is_active) {
      return res.status(403).json({ ok: false, error: 'Perfil inexistente o inactivo' });
    }

    return res.json({
      profile: {
        id: profile.id,
        firstName: profile.first_name,
        lastName: profile.last_name,
        role: profile.role_code,
        isActive: profile.is_active,
      },
    });
  } catch {
    console.error('Error al validar el perfil para configurar credenciales.');
    return res.status(503).json({ ok: false, error: 'No se pudo validar el perfil' });
  }
});

apiRouter.get('/auth/profile', async (req, res) => {
  const supabaseAdmin = req.app.locals.supabaseAdmin;
  const authorization = req.get('authorization') || '';
  const token = authorization.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!supabaseAdmin || !token) {
    return res.status(401).json({ ok: false, error: 'Sesión no válida' });
  }

  try {
    const { data: authData, error: authError } = await supabaseAdmin.auth.getUser(token);
    if (authError || !authData.user) {
      return res.status(401).json({ ok: false, error: 'Sesión no válida' });
    }

    const { data: profile, error: profileError } = await supabaseAdmin
      .from('profiles')
      .select('id, first_name, last_name, role_code, is_active')
      .eq('id', authData.user.id)
      .maybeSingle();

    if (profileError) {
      console.error('No se pudo validar el perfil de sesión.');
      return res.status(503).json({ ok: false, error: 'No se pudo validar el perfil' });
    }
    if (!profile || !profile.is_active) {
      return res.status(403).json({ ok: false, error: 'Perfil inexistente o inactivo' });
    }
    const { data: grants, error: permissionsError } = await resolveEffectivePermissions(supabaseAdmin, profile.role_code);
    if (permissionsError) {
      console.error('No se pudieron resolver los permisos para el acceso operativo.');
      return res.status(503).json({ ok: false, error: 'No se pudieron validar los permisos de la cuenta' });
    }
    const permissions = (grants || [])
      .filter(grant => grant.permissions?.code === grant.permission_code)
      .map(grant => grant.permissions.code);
    if (!permissions.includes('DASHBOARD_VIEW')) {
      return res.status(403).json({ ok: false, error: 'Esta cuenta no tiene permiso para acceder a la aplicación operativa' });
    }

    return res.json({
      profile: {
        id: profile.id,
        firstName: profile.first_name,
        lastName: profile.last_name,
        role: profile.role_code,
        isActive: profile.is_active,
        permissions,
      },
    });
  } catch {
    console.error('Error al validar la sesión de Supabase.');
    return res.status(503).json({ ok: false, error: 'No se pudo validar la sesión' });
  }
});

// Returns only the caller's effective permissions. This is informational in
// this stage; operational access remains guarded by /auth/profile and the
// administrative routes retain their independent ADMIN check.
apiRouter.get('/auth/permissions', async (req, res) => {
  const client = req.app.locals.supabaseAdmin;
  const token = (req.get('authorization') || '').match(/^Bearer\s+(.+)$/i)?.[1];
  res.set('Cache-Control', 'no-store');
  if (!client || !token) {
    return res.status(401).json({ ok: false, error: 'Sesión no válida' });
  }

  try {
    const { data: auth, error: authError } = await client.auth.getUser(token);
    if (authError || !auth.user) {
      return res.status(401).json({ ok: false, error: 'Sesión no válida' });
    }

    const { data: profile, error: profileError } = await client
      .from('profiles')
      .select('id, role_code, is_active')
      .eq('id', auth.user.id)
      .maybeSingle();

    if (profileError) {
      console.error('No se pudo validar el perfil para consultar permisos.');
      return res.status(503).json({ ok: false, error: 'No se pudieron consultar los permisos' });
    }
    if (!profile || !profile.is_active) {
      return res.status(403).json({ ok: false, error: 'Perfil inexistente o inactivo' });
    }

    const { data: rows, error: permissionsError } = await resolveEffectivePermissions(client, profile.role_code);

    if (permissionsError) {
      console.error('No se pudieron consultar los permisos efectivos del perfil.');
      return res.status(503).json({ ok: false, error: 'No se pudieron consultar los permisos' });
    }

    return res.json({
      role: profile.role_code,
      permissions: (rows || [])
        .filter(row => row.permissions?.code === row.permission_code)
        .map(row => row.permissions.code),
    });
  } catch {
    console.error('Error al consultar permisos efectivos del perfil.');
    return res.status(503).json({ ok: false, error: 'No se pudieron consultar los permisos' });
  }
});

const validRoles = new Set(['ADMIN', 'ENCARGADO', 'CAJERO', 'BARRA']);
const profileFields = 'id, first_name, last_name, role_code, is_active, created_at';

async function requireAdmin(req, res, next) {
  const client = req.app.locals.supabaseAdmin;
  const token = (req.get('authorization') || '').match(/^Bearer\s+(.+)$/i)?.[1];
  if (!client || !token) return res.status(401).json({ ok: false, error: 'Sesión no válida' });
  try {
    const { data: auth, error: authError } = await client.auth.getUser(token);
    if (authError || !auth.user) return res.status(401).json({ ok: false, error: 'Sesión no válida' });
    const { data: profile, error } = await client.from('profiles').select(profileFields).eq('id', auth.user.id).maybeSingle();
    if (error) return res.status(503).json({ ok: false, error: 'No se pudo validar el perfil' });
    if (!profile || !profile.is_active) return res.status(403).json({ ok: false, error: 'Perfil inexistente o inactivo' });
    if (profile.role_code !== 'ADMIN') return res.status(403).json({ ok: false, error: 'Se requiere rol Administrador' });
    req.adminIdentity = { id: auth.user.id, email: auth.user.email, profile };
    return next();
  } catch {
    return res.status(503).json({ ok: false, error: 'No se pudo validar la sesión' });
  }
}

const adminUsers = Router();
adminUsers.use(requireAdmin);

adminUsers.get('/', async (req, res) => {
  const client = req.app.locals.supabaseAdmin;
  try {
    const [{ data: profiles, error: profileError }, { data: authData, error: authError }] = await Promise.all([
      client.from('profiles').select(profileFields).order('created_at', { ascending: false }),
      client.auth.admin.listUsers({ page: 1, perPage: 1000 }),
    ]);
    if (profileError || authError) return res.status(503).json({ ok: false, error: 'No se pudo cargar la lista de usuarios' });
    const emails = new Map((authData.users || []).map(user => [user.id, user.email || '']));
    return res.json({ users: (profiles || []).map(profile => ({
      id: profile.id, firstName: profile.first_name, lastName: profile.last_name,
      email: emails.get(profile.id) || '', role: profile.role_code,
      isActive: profile.is_active, createdAt: profile.created_at,
    })) });
  } catch {
    return res.status(503).json({ ok: false, error: 'No se pudo cargar la lista de usuarios' });
  }
});

adminUsers.post('/', async (req, res) => {
  const client = req.app.locals.supabaseAdmin;
  const firstName = String(req.body?.firstName || '').trim();
  const lastName = String(req.body?.lastName || '').trim();
  const email = String(req.body?.email || '').trim().toLowerCase();
  const role = String(req.body?.role || '');
  if (!firstName || firstName.length > 100 || !lastName || lastName.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || !validRoles.has(role)) {
    return res.status(400).json({ ok: false, error: 'Revisá nombre, apellido, email y rol' });
  }
  try {
    const { data: existing, error: listError } = await client.auth.admin.listUsers({ page: 1, perPage: 1000 });
    if (listError) return res.status(503).json({ ok: false, error: 'No se pudo validar el email' });
    if ((existing.users || []).some(user => user.email?.toLowerCase() === email)) {
      return res.status(409).json({ ok: false, error: 'Ya existe una cuenta con ese email' });
    }
    const redirectTo = process.env.APP_URL || `http://localhost:${process.env.PORT || 4173}/`;
    const { data: invitation, error: inviteError } = await client.auth.admin.inviteUserByEmail(email, {
      data: { first_name: firstName, last_name: lastName },
      redirectTo,
    });
    if (inviteError || !invitation.user) {
      return res.status(502).json({ ok: false, error: 'No se pudo enviar la invitación' });
    }
    const { data: profile, error: insertError } = await client.from('profiles').insert({
      id: invitation.user.id, first_name: firstName, last_name: lastName, role_code: role, is_active: true,
    }).select(profileFields).single();
    if (insertError) {
      console.error('La invitación se creó, pero no se pudo crear su perfil.');
      return res.status(503).json({ ok: false, error: 'La invitación fue creada pero el perfil requiere revisión administrativa' });
    }
    return res.status(201).json({ user: {
      id: profile.id, firstName: profile.first_name, lastName: profile.last_name,
      email: invitation.user.email || email, role: profile.role_code,
      isActive: profile.is_active, createdAt: profile.created_at,
    } });
  } catch {
    return res.status(503).json({ ok: false, error: 'No se pudo completar la invitación' });
  }
});

adminUsers.patch('/:id', async (req, res) => {
  const client = req.app.locals.supabaseAdmin;
  const id = req.params.id;
  const firstName = String(req.body?.firstName || '').trim();
  const lastName = String(req.body?.lastName || '').trim();
  const role = String(req.body?.role || '');
  const isActive = req.body?.isActive;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id) || !firstName || firstName.length > 100 || !lastName || lastName.length > 100 || !validRoles.has(role) || typeof isActive !== 'boolean') {
    return res.status(400).json({ ok: false, error: 'Revisá los datos del perfil' });
  }
  try {
    const { data: profile, error } = await client.rpc('admin_update_profile', {
      p_profile_id: id, p_first_name: firstName, p_last_name: lastName,
      p_role_code: role, p_is_active: isActive,
    });
    if (error?.message?.includes('LAST_ACTIVE_ADMIN')) {
      return res.status(409).json({ ok: false, error: 'No se puede dejar el sistema sin Administradores activos' });
    }
    if (error) {
      console.error('No se pudo actualizar un perfil de usuario.');
      return res.status(error.code === 'P0002' ? 404 : 400).json({ ok: false, error: error.code === 'P0002' ? 'Usuario no encontrado' : 'No se pudo actualizar el usuario' });
    }
    const updated = Array.isArray(profile) ? profile[0] : profile;
    const { data: authData } = await client.auth.admin.getUserById(id);
    return res.json({ user: {
      id: updated.id, firstName: updated.first_name, lastName: updated.last_name,
      email: authData?.user?.email || '', role: updated.role_code,
      isActive: updated.is_active, createdAt: updated.created_at,
    } });
  } catch {
    return res.status(503).json({ ok: false, error: 'No se pudo actualizar el usuario' });
  }
});

apiRouter.use('/admin/users', adminUsers);

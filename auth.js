(() => {
  const app = document.getElementById('app');
  const screen = document.createElement('main');
  screen.id = 'auth-screen';
  screen.className = 'auth-screen';
  app.hidden = true;
  document.body.insertBefore(screen, app);

  let supabaseClient;
  let activeProfile;
  let sessionBar;
  let callbackType = '';
  let authInitialized = false;

  const roleNames = {
    ADMIN: 'Administrador',
    ENCARGADO: 'Encargado',
    CAJERO: 'Cajero',
    BARRA: 'Barra',
  };

  function callbackParams() {
    const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ''));
    const query = new URLSearchParams(window.location.search);
    return {
      type: fragment.get('type') || query.get('type') || '',
      error: fragment.get('error_code') || fragment.get('error') || query.get('error_code') || query.get('error') || '',
    };
  }

  function cleanCallbackUrl() {
    window.history.replaceState({}, document.title, window.location.pathname);
  }

  function linkErrorMessage() {
    return 'El enlace de invitación o recuperación es inválido o venció. Solicitá que te envíen uno nuevo.';
  }

  function renderAuth(mode = 'login', message = '') {
    app.hidden = true;
    if (sessionBar) sessionBar.remove();
    const invitation = mode === 'password' && callbackType === 'invite';
    const title = mode === 'password' ? 'Elegir contraseña' : mode === 'recovery' ? 'Recuperar acceso' : 'Ingresar a YambApp';
    const subtitle = mode === 'password'
      ? (invitation ? 'Definí una contraseña para completar la invitación.' : 'Definí una contraseña nueva para tu cuenta.')
      : mode === 'recovery' ? 'Te enviaremos un enlace para restablecer tu contraseña.' : 'Ingresá con tu cuenta de YambApp.';
    screen.innerHTML = `<section class="auth-card">
      <div class="auth-brand"><span class="auth-mark">Y</span><span>Yamb<span>App</span></span></div>
      <h1>${title}</h1><p class="auth-subtitle">${subtitle}</p>
      ${message ? `<div class="auth-message" role="status">${message}</div>` : ''}
      ${mode === 'login' ? `<form id="auth-login-form" class="auth-form">
        <label for="auth-email">Email</label><input id="auth-email" name="email" type="email" autocomplete="username" required>
        <label for="auth-password">Contraseña</label><input id="auth-password" name="password" type="password" autocomplete="current-password" required>
        <button class="auth-submit" type="submit">Ingresar</button>
        <button class="auth-link" type="button" id="auth-forgot">Olvidé mi contraseña</button>
      </form>` : mode === 'recovery' ? `<form id="auth-recovery-form" class="auth-form">
        <label for="auth-recovery-email">Email</label><input id="auth-recovery-email" name="email" type="email" autocomplete="email" required>
        <button class="auth-submit" type="submit">Enviar enlace</button>
        <button class="auth-link" type="button" id="auth-back">Volver al ingreso</button>
      </form>` : `<form id="auth-password-form" class="auth-form">
        <label for="auth-new-password">Nueva contraseña</label><input id="auth-new-password" name="password" type="password" autocomplete="new-password" minlength="8" required>
        <label for="auth-confirm-password">Repetir contraseña</label><input id="auth-confirm-password" name="confirmPassword" type="password" autocomplete="new-password" minlength="8" required>
        <button class="auth-submit" type="submit">Guardar contraseña</button>
      </form>`}
      <p class="auth-footnote">Las credenciales son administradas de forma segura por Supabase Auth.</p>
    </section>`;

    document.getElementById('auth-forgot')?.addEventListener('click', () => renderAuth('recovery'));
    document.getElementById('auth-back')?.addEventListener('click', () => renderAuth('login'));
    document.getElementById('auth-login-form')?.addEventListener('submit', signIn);
    document.getElementById('auth-recovery-form')?.addEventListener('submit', requestPasswordReset);
    document.getElementById('auth-password-form')?.addEventListener('submit', setPassword);
  }

  function friendlyAuthError(error) {
    const code = String(error?.code || '').toLowerCase();
    if (code.includes('expired') || code.includes('otp') || code.includes('token')) return linkErrorMessage();
    return 'No se pudo completar la solicitud. Revisá los datos e intentá nuevamente.';
  }

  async function fetchActiveProfile(accessToken) {
    const response = await fetch('/api/auth/profile', {
      headers: { Authorization: `Bearer ${accessToken}` },
      cache: 'no-store',
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) return { error: body.error || 'No se pudo validar el perfil.' };
    return { profile: body.profile };
  }

  function hasOperationalAccess(profile) {
    return Array.isArray(profile?.permissions) && profile.permissions.includes('DASHBOARD_VIEW');
  }

  async function fetchCredentialProfile(accessToken) {
    const response = await fetch('/api/auth/credential-profile', {
      headers: { Authorization: `Bearer ${accessToken}` },
      cache: 'no-store',
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) return { error: body.error || 'No se pudo validar el perfil.' };
    return { profile: body.profile };
  }

  async function apiFetch(path, options = {}) {
    const { data } = await supabaseClient.auth.getSession();
    if (!data.session?.access_token) throw new Error('Sesión no válida');
    const response = await fetch(path, {
      ...options,
      headers: { ...(options.headers || {}), Authorization: `Bearer ${data.session.access_token}` },
      cache: 'no-store',
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || 'No se pudo completar la solicitud');
    return body;
  }

  async function authorizeSession(session, passwordFlow = false) {
    if (!session?.access_token) {
      renderAuth('login', callbackType ? linkErrorMessage() : 'Iniciá sesión para continuar.');
      return;
    }

    if (passwordFlow || callbackType === 'invite' || callbackType === 'recovery') {
      const result = await fetchCredentialProfile(session.access_token);
      if (!result.profile) {
        await supabaseClient.auth.signOut({ scope: 'local' });
        activeProfile = null;
        window.yambaAuth = null;
        cleanCallbackUrl();
        renderAuth('login', result.error || 'No existe un perfil activo para esta cuenta.');
        return;
      }
      activeProfile = null;
      window.yambaAuth = null;
      renderAuth('password');
      return;
    }

    const result = await fetchActiveProfile(session.access_token);
    if (!result.profile) {
      await supabaseClient.auth.signOut({ scope: 'local' });
      cleanCallbackUrl();
      renderAuth('login', result.error || 'No existe un perfil activo para esta cuenta.');
      return;
    }
    if (!hasOperationalAccess(result.profile)) {
      await supabaseClient.auth.signOut({ scope: 'local' });
      cleanCallbackUrl();
      renderAuth('login', 'Esta cuenta todavía no tiene permisos para acceder a la aplicación operativa.');
      return;
    }

    activeProfile = result.profile;
    window.yambaAuth = { profile: activeProfile, permissions: activeProfile.permissions, signOut, apiFetch };
    cleanCallbackUrl();
    showApplication();
  }

  async function revalidateVisibleSession() {
    if (!activeProfile || document.hidden) return;
    const { data } = await supabaseClient.auth.getSession();
    if (!data.session?.access_token) return signOut();
    const result = await fetchActiveProfile(data.session.access_token);
    if (!result.profile || !hasOperationalAccess(result.profile)) {
      await supabaseClient.auth.signOut({ scope: 'local' });
      activeProfile = null;
      window.yambaAuth = null;
      renderAuth('login', result.error || 'Esta cuenta ya no tiene permisos para acceder a la aplicación operativa.');
      return;
    }
    activeProfile = result.profile;
    window.yambaAuth = { profile: activeProfile, permissions: activeProfile.permissions, signOut, apiFetch };
    window.render?.();
  }

  function showApplication() {
    screen.hidden = true;
    app.hidden = false;
    if (sessionBar) sessionBar.remove();
    sessionBar = document.createElement('div');
    sessionBar.className = 'auth-session-bar';
    const identity = document.createElement('span');
    identity.textContent = `${activeProfile.firstName} ${activeProfile.lastName} · ${roleNames[activeProfile.role] || activeProfile.role}`;
    const logout = document.createElement('button');
    logout.type = 'button';
    logout.textContent = 'Cerrar sesión';
    logout.addEventListener('click', signOut);
    sessionBar.append(identity, logout);
    document.body.appendChild(sessionBar);
    window.render?.();
  }

  async function signIn(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const { data, error } = await supabaseClient.auth.signInWithPassword({
      email: String(form.get('email')).trim(),
      password: String(form.get('password')),
    });
    if (error) {
      renderAuth('login', friendlyAuthError(error));
      return;
    }
    callbackType = '';
    await authorizeSession(data.session);
  }

  async function requestPasswordReset(event) {
    event.preventDefault();
    const email = String(new FormData(event.currentTarget).get('email')).trim();
    const { error } = await supabaseClient.auth.resetPasswordForEmail(email, { redirectTo: `${window.location.origin}/` });
    renderAuth('recovery', error ? friendlyAuthError(error) : 'Si la cuenta existe, recibirás un enlace para restablecer la contraseña.');
  }

  async function setPassword(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const password = String(form.get('password'));
    const confirmation = String(form.get('confirmPassword'));
    if (password.length < 8) {
      renderAuth('password', 'La contraseña debe tener al menos 8 caracteres.');
      return;
    }
    if (password !== confirmation) {
      renderAuth('password', 'Las contraseñas no coinciden.');
      return;
    }

    const { data: current } = await supabaseClient.auth.getSession();
    if (!current.session?.access_token) {
      await supabaseClient.auth.signOut({ scope: 'local' });
      cleanCallbackUrl();
      renderAuth('login', linkErrorMessage());
      return;
    }
    const active = await fetchCredentialProfile(current.session.access_token);
    if (!active.profile) {
      await supabaseClient.auth.signOut({ scope: 'local' });
      activeProfile = null;
      window.yambaAuth = null;
      cleanCallbackUrl();
      renderAuth('login', active.error || 'El perfil no está activo. Contactá a un Administrador.');
      return;
    }

    const { error } = await supabaseClient.auth.updateUser({ password });
    if (error) {
      renderAuth('password', friendlyAuthError(error));
      return;
    }
    const { data: updatedSession } = await supabaseClient.auth.getSession();
    callbackType = '';
    cleanCallbackUrl();
    await authorizeSession(updatedSession.session);
  }

  async function signOut() {
    await supabaseClient?.auth.signOut({ scope: 'local' });
    activeProfile = null;
    callbackType = '';
    window.yambaAuth = null;
    cleanCallbackUrl();
    renderAuth('login', 'Sesión cerrada.');
  }

  async function initialize() {
    const callback = callbackParams();
    callbackType = callback.type;
    if (callback.error) {
      renderAuth('login', linkErrorMessage());
      return;
    }
    try {
      const configResponse = await fetch('/api/config', { cache: 'no-store' });
      const config = await configResponse.json();
      if (!configResponse.ok || !window.supabase?.createClient) throw new Error('auth_config');
      supabaseClient = window.supabase.createClient(config.supabaseUrl, config.publishableKey, {
        auth: { detectSessionInUrl: true, persistSession: true, autoRefreshToken: true },
      });
      supabaseClient.auth.onAuthStateChange((event, session) => {
        if (event === 'SIGNED_OUT') {
          activeProfile = null;
          window.yambaAuth = null;
          if (authInitialized) renderAuth('login');
        } else if (event === 'PASSWORD_RECOVERY' && session) {
          callbackType = 'recovery';
          if (authInitialized) queueMicrotask(() => authorizeSession(session, true));
        }
      });
      const { data, error } = await supabaseClient.auth.getSession();
      if (error) {
        renderAuth('login', friendlyAuthError(error));
        return;
      }
      if (!data.session && (callbackType === 'invite' || callbackType === 'recovery')) {
        renderAuth('login', linkErrorMessage());
        return;
      }
      await authorizeSession(data.session);
      authInitialized = true;
      window.addEventListener('focus', revalidateVisibleSession);
      document.addEventListener('visibilitychange', revalidateVisibleSession);
      window.setInterval(revalidateVisibleSession, 45000);
    } catch {
      renderAuth('login', 'No se pudo conectar con el servicio de autenticación. Intentá nuevamente.');
    }
  }

  renderAuth('login');
  initialize();
})();

import { createClient } from '@supabase/supabase-js';

/**
 * Creates a server-only Supabase client when backend credentials are configured.
 * The service role key must never be returned to or bundled into the browser.
 */
export function createSupabaseAdminClient(env = process.env) {
  const url = env.SUPABASE_URL;
  const serviceRoleKey = env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url && !serviceRoleKey) return null;
  if (!url || !serviceRoleKey) {
    throw new Error('SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY deben configurarse juntas.');
  }

  return createClient(url, serviceRoleKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });
}


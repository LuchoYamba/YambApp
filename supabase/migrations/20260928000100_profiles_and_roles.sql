-- Base de identidad de YambApp.
-- Las identidades y credenciales viven en Supabase Auth; public.profiles guarda
-- únicamente datos de aplicación y referencia auth.users mediante su UUID.

CREATE TABLE IF NOT EXISTS public.roles (
  code text PRIMARY KEY,
  name text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT '',
  is_system boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT roles_code_format CHECK (code ~ '^[A-Z][A-Z0-9_]*$')
);

INSERT INTO public.roles (code, name, description)
VALUES
  ('ADMIN', 'Administrador', 'Control total del sistema.'),
  ('ENCARGADO', 'Encargado', 'Control operativo de la jornada.'),
  ('CAJERO', 'Cajero', 'Rol inicial para operaciones de caja.'),
  ('BARRA', 'Barra', 'Rol inicial para operaciones de barra.')
ON CONFLICT (code) DO NOTHING;

-- Catálogo futuro de permisos. Esta etapa no define permisos operativos.
CREATE TABLE IF NOT EXISTS public.role_permissions (
  role_code text NOT NULL REFERENCES public.roles(code) ON UPDATE RESTRICT ON DELETE RESTRICT,
  permission_code text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (role_code, permission_code),
  CONSTRAINT role_permissions_code_format CHECK (permission_code ~ '^[a-z][a-z0-9_.:-]*$')
);

CREATE TABLE IF NOT EXISTS public.profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  first_name text NOT NULL,
  last_name text NOT NULL,
  role_code text NOT NULL REFERENCES public.roles(code) ON UPDATE RESTRICT ON DELETE RESTRICT,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT profiles_first_name_not_blank CHECK (length(btrim(first_name)) > 0),
  CONSTRAINT profiles_last_name_not_blank CHECK (length(btrim(last_name)) > 0)
);

CREATE INDEX IF NOT EXISTS profiles_role_code_idx ON public.profiles (role_code);
CREATE INDEX IF NOT EXISTS profiles_active_idx ON public.profiles (is_active);

CREATE OR REPLACE FUNCTION public.set_profiles_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_trigger
    WHERE tgname = 'profiles_set_updated_at'
      AND tgrelid = 'public.profiles'::regclass
      AND NOT tgisinternal
  ) THEN
    CREATE TRIGGER profiles_set_updated_at
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.set_profiles_updated_at();
  END IF;
END;
$$;

ALTER TABLE public.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- No browser role receives table access in this foundation migration.
-- Future API endpoints will authorize using the validated Supabase identity.
REVOKE ALL ON TABLE public.roles, public.role_permissions, public.profiles
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.set_profiles_updated_at() FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.roles, public.role_permissions, public.profiles TO service_role;

COMMENT ON TABLE public.roles IS 'YambApp roles. Codes are controlled by versioned migrations.';
COMMENT ON TABLE public.role_permissions IS 'Reserved mapping for future role permissions; no operational grants are defined yet.';
COMMENT ON TABLE public.profiles IS 'YambApp profile, one row per Supabase Auth identity. Disable with is_active=false; do not physically delete for ordinary offboarding.';
COMMENT ON COLUMN public.profiles.id IS 'One-to-one UUID reference to auth.users.id; RESTRICT prevents routine physical identity deletion.';
COMMENT ON COLUMN public.profiles.role_code IS 'Single primary YambApp role; authorization must not trust a browser-supplied role.';

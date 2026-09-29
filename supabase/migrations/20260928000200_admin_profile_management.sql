-- Serializa cambios de perfiles para impedir que dos operaciones simultaneas
-- desactiven/promuevan administradores y dejen el sistema sin un ADMIN activo.
CREATE OR REPLACE FUNCTION public.admin_update_profile(
  p_profile_id uuid,
  p_first_name text,
  p_last_name text,
  p_role_code text,
  p_is_active boolean
)
RETURNS public.profiles
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_active_admin_count integer;
  v_current public.profiles;
  v_updated public.profiles;
BEGIN
  IF p_first_name IS NULL OR length(btrim(p_first_name)) = 0 OR length(p_first_name) > 100
     OR p_last_name IS NULL OR length(btrim(p_last_name)) = 0 OR length(p_last_name) > 100
     OR p_role_code NOT IN ('ADMIN', 'ENCARGADO', 'CAJERO', 'BARRA')
     OR p_is_active IS NULL THEN
    RAISE EXCEPTION 'INVALID_PROFILE';
  END IF;

  -- Lock all active administrator rows in stable order to serialize demotions.
  PERFORM id FROM public.profiles
   WHERE role_code = 'ADMIN' AND is_active = true
   ORDER BY id FOR UPDATE;
  SELECT count(*) INTO v_active_admin_count
    FROM public.profiles WHERE role_code = 'ADMIN' AND is_active = true;

  SELECT * INTO v_current FROM public.profiles WHERE id = p_profile_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'PROFILE_NOT_FOUND' USING ERRCODE = 'P0002'; END IF;

  IF v_current.role_code = 'ADMIN' AND v_current.is_active
     AND (p_role_code <> 'ADMIN' OR p_is_active = false)
     AND v_active_admin_count <= 1 THEN
    RAISE EXCEPTION 'LAST_ACTIVE_ADMIN';
  END IF;

  UPDATE public.profiles
     SET first_name = btrim(p_first_name), last_name = btrim(p_last_name),
         role_code = p_role_code, is_active = p_is_active
   WHERE id = p_profile_id
   RETURNING * INTO v_updated;
  RETURN v_updated;
END;
$$;

REVOKE ALL ON FUNCTION public.admin_update_profile(uuid, text, text, text, boolean)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_update_profile(uuid, text, text, text, boolean)
  TO service_role;

COMMENT ON FUNCTION public.admin_update_profile(uuid, text, text, text, boolean)
  IS 'Backend-only profile update with a serialized guard against removing the final active ADMIN.';

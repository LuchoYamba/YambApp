-- Catálogo de permisos de YambApp y asignaciones iniciales por rol.
-- La autorización seguirá resolviéndose en backend; RLS y los grants de
-- navegador permanecen cerrados.

CREATE TABLE IF NOT EXISTS public.permissions (
  code text PRIMARY KEY,
  name text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT '',
  is_system boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT permissions_code_format CHECK (code ~ '^[A-Z][A-Z0-9_]*$')
);

INSERT INTO public.permissions (code, name, description)
VALUES
  ('DASHBOARD_VIEW', 'Ver panel principal', 'Consultar el panel principal.'),
  ('SALE_CREATE', 'Crear ventas', 'Registrar una venta.'),
  ('SALE_VIEW_ALL', 'Ver todas las ventas', 'Consultar ventas sin limitarse a una caja.'),
  ('SALE_VOID', 'Anular ventas', 'Anular una venta.'),
  ('DISCOUNT_EXCEPTIONAL', 'Aplicar descuentos excepcionales', 'Aplicar descuentos excepcionales.'),
  ('INVOICE_CREATE', 'Crear comprobantes', 'Crear comprobantes de venta.'),
  ('COURTESY_CREATE', 'Crear cortesías', 'Registrar cortesías.'),
  ('QR_REDEEM', 'Canjear QR', 'Canjear tickets QR.'),
  ('QR_REVERSE', 'Revertir canje QR', 'Revertir un canje QR.'),
  ('PRODUCT_MANAGE', 'Administrar productos', 'Crear y editar productos.'),
  ('PRICE_CHANGE', 'Cambiar precios', 'Modificar precios de productos.'),
  ('STOCK_VIEW_ALL', 'Ver stock general', 'Consultar el stock general.'),
  ('STOCK_ADJUST', 'Ajustar stock', 'Registrar ajustes de stock.'),
  ('REPLENISHMENT_REQUEST', 'Solicitar reposiciones', 'Solicitar reposiciones.'),
  ('REPLENISHMENT_MANAGE', 'Administrar reposiciones', 'Gestionar solicitudes de reposición.'),
  ('WAREHOUSE_MANAGE', 'Administrar depósito', 'Administrar el depósito central.'),
  ('STOCK_TRANSFER', 'Transferir stock', 'Transferir stock entre ubicaciones.'),
  ('STOCK_OPEN_CLOSE', 'Abrir y cerrar stock', 'Registrar aperturas y cierres de stock.'),
  ('CASH_OPERATE', 'Operar caja', 'Registrar operaciones de caja.'),
  ('CASH_CLOSE', 'Cerrar caja', 'Realizar cierres de caja.'),
  ('CASH_VIEW_ALL', 'Ver todas las cajas', 'Consultar información de todas las cajas.'),
  ('CASH_REOPEN', 'Reabrir caja', 'Reabrir una caja cerrada.'),
  ('AUDIT_VIEW', 'Consultar auditoría', 'Consultar registros de auditoría.'),
  ('USER_MANAGE_OPERATIONAL', 'Administrar usuarios operativos', 'Administrar usuarios Cajero y Barra.'),
  ('USER_MANAGE_ENCARGADO', 'Administrar encargados', 'Administrar usuarios Encargado.'),
  ('USER_MANAGE_ADMIN', 'Administrar administradores', 'Administrar usuarios Administrador.'),
  ('PERMISSION_MANAGE', 'Administrar permisos', 'Administrar permisos asignados a roles.'),
  ('SYSTEM_CONFIG', 'Configurar sistema', 'Modificar la configuración del sistema.'),
  ('SENSITIVE_AUTHORIZE', 'Autorizar acciones sensibles', 'Autorizar acciones sensibles.')
ON CONFLICT (code) DO NOTHING;

-- role_permissions ya existe desde la migración base. Su restricción original
-- aceptaba únicamente códigos minúsculos; se adapta al catálogo controlado.
ALTER TABLE public.role_permissions
  DROP CONSTRAINT IF EXISTS role_permissions_code_format;
ALTER TABLE public.role_permissions
  ADD CONSTRAINT role_permissions_code_format
  CHECK (permission_code ~ '^[A-Z][A-Z0-9_]*$');

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'role_permissions_permission_code_fkey'
      AND conrelid = 'public.role_permissions'::regclass
  ) THEN
    ALTER TABLE public.role_permissions
      ADD CONSTRAINT role_permissions_permission_code_fkey
      FOREIGN KEY (permission_code) REFERENCES public.permissions(code)
      ON UPDATE RESTRICT ON DELETE RESTRICT;
  END IF;
END;
$$;

-- ADMIN receives the full catalog. Other role grants are intentionally narrow.
INSERT INTO public.role_permissions (role_code, permission_code)
SELECT 'ADMIN', code FROM public.permissions
ON CONFLICT (role_code, permission_code) DO NOTHING;

INSERT INTO public.role_permissions (role_code, permission_code)
VALUES
  ('ENCARGADO', 'DASHBOARD_VIEW'),
  ('ENCARGADO', 'SALE_CREATE'),
  ('ENCARGADO', 'SALE_VIEW_ALL'),
  ('ENCARGADO', 'SALE_VOID'),
  ('ENCARGADO', 'DISCOUNT_EXCEPTIONAL'),
  ('ENCARGADO', 'INVOICE_CREATE'),
  ('ENCARGADO', 'COURTESY_CREATE'),
  ('ENCARGADO', 'QR_REDEEM'),
  ('ENCARGADO', 'QR_REVERSE'),
  ('ENCARGADO', 'PRODUCT_MANAGE'),
  ('ENCARGADO', 'PRICE_CHANGE'),
  ('ENCARGADO', 'STOCK_VIEW_ALL'),
  ('ENCARGADO', 'STOCK_ADJUST'),
  ('ENCARGADO', 'REPLENISHMENT_REQUEST'),
  ('ENCARGADO', 'REPLENISHMENT_MANAGE'),
  ('ENCARGADO', 'WAREHOUSE_MANAGE'),
  ('ENCARGADO', 'STOCK_TRANSFER'),
  ('ENCARGADO', 'STOCK_OPEN_CLOSE'),
  ('ENCARGADO', 'CASH_OPERATE'),
  ('ENCARGADO', 'CASH_CLOSE'),
  ('ENCARGADO', 'CASH_VIEW_ALL'),
  ('ENCARGADO', 'CASH_REOPEN'),
  ('ENCARGADO', 'AUDIT_VIEW'),
  ('ENCARGADO', 'USER_MANAGE_OPERATIONAL'),
  ('ENCARGADO', 'SENSITIVE_AUTHORIZE'),
  ('CAJERO', 'SALE_CREATE'),
  ('CAJERO', 'INVOICE_CREATE'),
  ('CAJERO', 'CASH_OPERATE'),
  ('CAJERO', 'CASH_CLOSE'),
  ('BARRA', 'QR_REDEEM'),
  ('BARRA', 'REPLENISHMENT_REQUEST')
ON CONFLICT (role_code, permission_code) DO NOTHING;

ALTER TABLE public.permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.role_permissions ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.permissions, public.role_permissions
  FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.permissions, public.role_permissions TO service_role;

COMMENT ON TABLE public.permissions IS 'Versioned catalog of YambApp permission codes.';
COMMENT ON TABLE public.role_permissions IS 'Effective permission grants by controlled YambApp role.';
COMMENT ON COLUMN public.role_permissions.permission_code IS 'References the versioned public.permissions catalog.';

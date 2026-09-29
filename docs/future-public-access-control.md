# Requisitos futuros: personal externo y control de acceso

Estos conceptos quedan fuera del módulo interno de Usuarios y de los cuatro roles ADMIN, ENCARGADO, CAJERO y BARRA. No se implementan en la etapa actual.

## Personal externo / Públicas-RRPP

- Permitir cuentas diferenciadas para personal externo de Públicas/RRPP.
- Registrar asistencia con eventos de ingreso y egreso.
- Aplicar beneficios y consumiciones según el horario correspondiente.

## Control de acceso y aforo

- Definir un permiso específico de Control de Acceso/Aforo, sin mezclarlo con los cuatro roles internos actuales.
- Registrar eventos de `+1 entrada` y `-1 salida`.
- Calcular ocupación actual e ingresos acumulados.
- Conservar el pico de ocupación y su horario.
- Permitir reconstruir históricamente el aforo a partir de los eventos registrados.

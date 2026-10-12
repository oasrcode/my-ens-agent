# Informe de cumplimiento del ENS

> _Generado automáticamente por `ens_audit`._

## Metadatos

| Campo | Valor |
|---|---|
| Sistema | juice-shop |
| Categoría | ALTA |
| Fecha | 2026-10-12 18:53 UTC |
| Norma | BOE-A-2022-7191 |
| Versión del catálogo | 1.0.0 |

## Resumen ejecutivo

Se han evaluado **73** medidas del catálogo ENS.

- **Cumplimiento:** **0.0 %** (0 / 73 medidas aplicables).
- **Cobertura de evaluación:** **52.05 %** (38 / 73 medidas aplicables).

| Veredicto | Nº de medidas | % del total |
|---|---:|---:|
| Cumple | 0 | 0.0 % |
| No cumple | 19 | 26.03 % |
| Parcial | 19 | 26.03 % |
| No aplica | 0 | 0.0 % |
| No evaluable | 35 | 47.95 % |

### Estados de la evidencia

_Recuento de medidas según el estado de la evidencia: no comprobado, no detectado, riesgo detectado, no concluyente, cumplimiento demostrado e incumplimiento demostrado._

| Estado de la evidencia | Nº de medidas |
|---|---:|
| No comprobado | 35 |
| No detectado | 1 |
| Riesgo detectado | 0 |
| No concluyente | 18 |
| Cumplimiento demostrado | 0 |
| Incumplimiento demostrado | 19 |

## Alcance y metodología

Alcance: se auditan las **73** medidas de seguridad del Anexo II del ENS (BOE-A-2022-7191) presentes en el catálogo OSCAL de referencia.

Metodología: los veredictos se consolidan con `evaluate_compliance` siguiendo este orden de precedencia: (1) evaluación manual explícita; (2) aplicabilidad según la categoría del sistema; (3) hallazgos de los escáneres que demuestran incumplimiento de un requisito aplicable (no conformidad mayor); (4) señales de riesgo no demostrativas (por ejemplo, vulnerabilidades detectadas o dependencias sin fijar), que acotan la medida a parcial y se listan como riesgos sin forzar un incumplimiento; (5) evidencia positiva registrada por los escáneres; y (6) sin evidencia ni valoración, la medida se marca como no evaluable (la ausencia de hallazgos no es prueba de cumplimiento).

- Escáneres ejecutados: code.sast, code.crypto, code.dependencies, code.logging, code.secrets, infra.backup, infra.compose, infra.dockerfile, infra.terraform, infra.web.
- Hallazgos registrados: 760.
- Medidas aplicables: 73.

## Categorización

El sistema evaluado se clasifica en la categoría **ALTA**. La aplicabilidad de cada medida se deriva de esa categoría y de la valoración de las dimensiones de seguridad (confidencialidad, integridad, disponibilidad, autenticidad y trazabilidad) conforme al Anexo I del RD 311/2022.

## Dimensiones y refuerzos

_Valoración de las dimensiones de seguridad y refuerzos activados a partir de ella._

| Dimensión | Nivel |
|---|---|
| Confidencialidad | ALTO |
| Integridad | ALTO |
| Disponibilidad | ALTO |
| Autenticidad | ALTO |
| Trazabilidad | ALTO |

### Refuerzos activados

- `mp.com.2`: `mp.com.2.r1`, `mp.com.2.r2`, `mp.com.2.r3`.
- `mp.com.3`: `mp.com.3.r1`, `mp.com.3.r2`, `mp.com.3.r3`, `mp.com.3.r4`.
- `mp.com.4`: `mp.com.4.r2`, `mp.com.4.r3`, `mp.com.4.r4`.
- `mp.eq.1`: `mp.eq.1.r1`.
- `mp.eq.2`: `mp.eq.2.r1`.
- `mp.eq.3`: `mp.eq.3.r1`, `mp.eq.3.r2`.
- `mp.eq.4`: `mp.eq.4.r1`.
- `mp.if.4`: `mp.if.4.r1`.
- `mp.info.3`: `mp.info.3.r1`, `mp.info.3.r2`, `mp.info.3.r3`, `mp.info.3.r4`.
- `mp.info.6`: `mp.info.6.r1`, `mp.info.6.r2`.
- `mp.per.2`: `mp.per.2.r1`.
- `mp.s.2`: `mp.s.2.r2`, `mp.s.2.r3`.
- `mp.s.3`: `mp.s.3.r1`.
- `mp.s.4`: `mp.s.4.r1`.
- `mp.si.2`: `mp.si.2.r1`, `mp.si.2.r2`.
- `mp.si.5`: `mp.si.5.r1`.
- `mp.sw.1`: `mp.sw.1.r1`, `mp.sw.1.r2`, `mp.sw.1.r3`, `mp.sw.1.r4`.
- `mp.sw.2`: `mp.sw.2.r1`.
- `op.acc.1`: `op.acc.1.r1`.
- `op.acc.2`: `op.acc.2.r1`.
- `op.acc.3`: `op.acc.3.r1`.
- `op.acc.5`: `op.acc.5.r2`, `op.acc.5.r3`, `op.acc.5.r4`, `op.acc.5.r5`.
- `op.acc.6`: `op.acc.6.r1`, `op.acc.6.r2`, `op.acc.6.r3`, `op.acc.6.r4`, `op.acc.6.r5`, `op.acc.6.r6`, `op.acc.6.r7`, `op.acc.6.r8`, `op.acc.6.r9`.
- `op.exp.10`: `op.exp.10.r1`.
- `op.exp.3`: `op.exp.3.r1`, `op.exp.3.r2`, `op.exp.3.r3`.
- `op.exp.4`: `op.exp.4.r1`, `op.exp.4.r2`.
- `op.exp.5`: `op.exp.5.r1`.
- `op.exp.6`: `op.exp.6.r1`, `op.exp.6.r2`, `op.exp.6.r3`, `op.exp.6.r4`.
- `op.exp.7`: `op.exp.7.r1`, `op.exp.7.r2`, `op.exp.7.r3`.
- `op.exp.8`: `op.exp.8.r1`, `op.exp.8.r2`, `op.exp.8.r3`, `op.exp.8.r4`, `op.exp.8.r5`.
- `op.ext.4`: `op.ext.4.r1`.
- `op.mon.1`: `op.mon.1.r1`, `op.mon.1.r2`.
- `op.mon.2`: `op.mon.2.r1`, `op.mon.2.r2`.
- `op.mon.3`: `op.mon.3.r1`, `op.mon.3.r2`, `op.mon.3.r3`, `op.mon.3.r4`, `op.mon.3.r5`, `op.mon.3.r6`.
- `op.nub.1`: `op.nub.1.r1`, `op.nub.1.r2`.
- `op.pl.1`: `op.pl.1.r2`.
- `op.pl.2`: `op.pl.2.r1`, `op.pl.2.r2`, `op.pl.2.r3`.
- `op.pl.4`: `op.pl.4.r1`.

## Evidencia positiva

_Comprobaciones de escáner con resultado favorable: qué se comprobó, alcance y fecha._

| Escáner | Comprobado | Resultado | Alcance | Fecha |
|---|---|---|---|---|
| `infra.backup` | Copias de seguridad y su retención | correcto | juice-shop (46 files) | 2026-10-12 |
| `infra.compose` | Modo de depuración en la configuración de producción | correcto | juice-shop (5 files) | 2026-10-12 |
| `infra.compose` | Credenciales y claves embebidas en el código fuente | correcto | juice-shop (5 files) | 2026-10-12 |
| `infra.dockerfile` | Credenciales y claves embebidas en el código fuente | correcto | juice-shop (3 files) | 2026-10-12 |

## Estado de los escáneres

_Resultado de la ejecución de cada escáner._

| Escáner | Estado |
|---|---|
| `code.crypto` | Completado |
| `code.dependencies` | Completado |
| `code.logging` | Completado |
| `code.sast` | Completado |
| `code.secrets` | Completado |
| `infra.backup` | Completado |
| `infra.compose` | Completado |
| `infra.dockerfile` | Completado |
| `infra.terraform` | Completado |
| `infra.web` | Omitido |

## Tabla completa de medidas

| Código | Medida | Marco / Familia | Estado de la evidencia | Requisitos / Refuerzos | Trazabilidad | Veredicto |
|---|---|---|---|---|---|---|
| `org.1` | Política de seguridad | org / Marco organizativo | No comprobado | REQ: org.1.req.1, org.1.req.2, org.1.req.3, org.1.req.4, org.1.req.5 | — | No evaluable |
| `org.2` | Normativa de seguridad | org / Marco organizativo | No comprobado | REQ: org.2.req.1, org.2.req.2 | — | No evaluable |
| `org.3` | Procedimientos de seguridad | org / Marco organizativo | No comprobado | REQ: org.3.req.1, org.3.req.2, org.3.req.3, org.3.req.4, org.3.req.4.a, org.3.req.4.b, org.3.req.4.c, org.3.req.4.d, org.3.req.4.e, org.3.req.4.f | — | No evaluable |
| `org.4` | Proceso de autorización | org / Marco organizativo | No comprobado | REQ: org.4.req.1, org.4.req.2, org.4.req.3, org.4.req.4, org.4.req.5, org.4.req.6, org.4.req.7, org.4.req.8 | — | No evaluable |
| `op.pl.1` | Análisis de riesgos | op / Planificación | No concluyente | REQ: op.pl.1.r2.req.1, op.pl.1.r2.req.2, op.pl.1.r2.req.3, op.pl.1.r2.req.4, op.pl.1.req.1, op.pl.1.req.2, op.pl.1.req.3, op.pl.1.req.4 · REF: op.pl.1.r2 | — | Parcial |
| `op.pl.2` | Arquitectura de seguridad | op / Planificación | No concluyente | REQ: op.pl.2.r1.req.1, op.pl.2.r2.req.1, op.pl.2.r3.req.1, op.pl.2.req.1, op.pl.2.req.2, op.pl.2.req.3, op.pl.2.req.4 · REF: op.pl.2.r1, op.pl.2.r2, op.pl.2.r3 | — | Parcial |
| `op.pl.3` | Adquisición de nuevos componentes | op / Planificación | No concluyente | REQ: op.pl.3.req.1, op.pl.3.req.2, op.pl.3.req.3 | — | Parcial |
| `op.pl.4` | Dimensionamiento / gestión de la capacidad | op / Planificación | No concluyente | REQ: op.pl.4.r1.req.1, op.pl.4.r1.req.2, op.pl.4.req.1, op.pl.4.req.2, op.pl.4.req.3, op.pl.4.req.4, op.pl.4.req.5 · REF: op.pl.4.r1 | — | Parcial |
| `op.pl.5` | Componentes certificados | op / Planificación | Incumplimiento demostrado | REQ: op.pl.5.req.1, op.pl.5.req.2 | — | No cumple |
| `op.acc.1` | Identificación | op / Control de acceso | No concluyente | REQ: op.acc.1.r1.req.1, op.acc.1.r1.req.2, op.acc.1.r1.req.3, op.acc.1.req.1, op.acc.1.req.2, op.acc.1.req.3, op.acc.1.req.4, op.acc.1.req.4.a, op.acc.1.req.4.b, op.acc.1.req.4.c, op.acc.1.req.5, op.acc.1.req.5.a, op.acc.1.req.5.b, op.acc.1.req.5.c · REF: op.acc.1.r1 | — | Parcial |
| `op.acc.2` | Requisitos de acceso | op / Control de acceso | Incumplimiento demostrado | REQ: op.acc.2.r1.req.1, op.acc.2.r1.req.2, op.acc.2.req.1, op.acc.2.req.2, op.acc.2.req.3 · REF: op.acc.2.r1 | — | No cumple |
| `op.acc.3` | Segregación de funciones y tareas | op / Control de acceso | No comprobado | REQ: op.acc.3.r1.req.1, op.acc.3.r1.req.2, op.acc.3.req.1, op.acc.3.req.2 · REF: op.acc.3.r1 | — | No evaluable |
| `op.acc.4` | Proceso de gestión de derechos de acceso | op / Control de acceso | Incumplimiento demostrado | REQ: op.acc.4.req.1, op.acc.4.req.2, op.acc.4.req.3, op.acc.4.req.4, op.acc.4.req.5 | — | No cumple |
| `op.acc.5` | Mecanismo de autenticación (usuarios externos) | op / Control de acceso | Incumplimiento demostrado | REQ: op.acc.5.r2.req.1, op.acc.5.r3.req.1, op.acc.5.r3.req.2, op.acc.5.r3.req.3, op.acc.5.r4.req.1, op.acc.5.r4.req.2, op.acc.5.r4.req.3, op.acc.5.r5.req.1, op.acc.5.r5.req.2, op.acc.5.req.1, op.acc.5.req.2, op.acc.5.req.3, op.acc.5.req.4, op.acc.5.req.5, op.acc.5.req.6, op.acc.5.req.7, op.acc.5.req.8, op.acc.5.req.9 · REF: op.acc.5.r2, op.acc.5.r3, op.acc.5.r4, op.acc.5.r5 | — | No cumple |
| `op.acc.6` | Mecanismo de autenticación (usuarios de la organización) | op / Control de acceso | Incumplimiento demostrado | REQ: op.acc.6.r1.req.1, op.acc.6.r1.req.2, op.acc.6.r2.req.1, op.acc.6.r3.req.1, op.acc.6.r3.req.2, op.acc.6.r4.req.1, op.acc.6.r4.req.2, op.acc.6.r5.req.1, op.acc.6.r5.req.2, op.acc.6.r6.req.1, op.acc.6.r7.req.1, op.acc.6.r8.req.1, op.acc.6.r9.req.1, op.acc.6.r9.req.2, op.acc.6.r9.req.2.a, op.acc.6.r9.req.2.b, op.acc.6.r9.req.2.c, op.acc.6.r9.req.2.d, op.acc.6.req.1, op.acc.6.req.2, op.acc.6.req.3, op.acc.6.req.4, op.acc.6.req.5, op.acc.6.req.6, op.acc.6.req.7, op.acc.6.req.8, op.acc.6.req.9 · REF: op.acc.6.r1, op.acc.6.r2, op.acc.6.r3, op.acc.6.r4, op.acc.6.r5, op.acc.6.r6, op.acc.6.r7, op.acc.6.r8, op.acc.6.r9 | — | No cumple |
| `op.exp.1` | Inventario de activos | op / Explotación | No concluyente | REQ: op.exp.1.req.1 | — | Parcial |
| `op.exp.2` | Configuración de seguridad | op / Explotación | Incumplimiento demostrado | REQ: op.exp.2.req.1, op.exp.2.req.2, op.exp.2.req.2.a, op.exp.2.req.2.b, op.exp.2.req.3, op.exp.2.req.3.a, op.exp.2.req.3.b, op.exp.2.req.3.c, op.exp.2.req.4 | infra.dockerfile (heurístico, media), infra.compose (heurístico, media) | No cumple |
| `op.exp.3` | Gestión de la configuración de seguridad | op / Explotación | No concluyente | REQ: op.exp.3.r1.req.1, op.exp.3.r1.req.2, op.exp.3.r1.req.3, op.exp.3.r2.req.1, op.exp.3.r3.req.1, op.exp.3.req.1, op.exp.3.req.2, op.exp.3.req.3, op.exp.3.req.4, op.exp.3.req.5, op.exp.3.req.6 · REF: op.exp.3.r1, op.exp.3.r2, op.exp.3.r3 | — | Parcial |
| `op.exp.4` | Mantenimiento y actualizaciones de seguridad | op / Explotación | Incumplimiento demostrado | REQ: op.exp.4.r1.req.1, op.exp.4.r2.req.1, op.exp.4.req.1, op.exp.4.req.2, op.exp.4.req.3 · REF: op.exp.4.r1, op.exp.4.r2 | code.dependencies (heurístico, media), infra.dockerfile (heurístico, media) | No cumple |
| `op.exp.5` | Gestión de cambios | op / Explotación | No concluyente | REQ: op.exp.5.r1.req.1, op.exp.5.r1.req.2, op.exp.5.r1.req.3, op.exp.5.req.1, op.exp.5.req.2, op.exp.5.req.3, op.exp.5.req.4, op.exp.5.req.5 · REF: op.exp.5.r1 | — | Parcial |
| `op.exp.6` | Protección frente a código dañino | op / Explotación | Incumplimiento demostrado | REQ: op.exp.6.r1.req.1, op.exp.6.r2.req.1, op.exp.6.r3.req.1, op.exp.6.r4.req.1, op.exp.6.req.1, op.exp.6.req.2, op.exp.6.req.3, op.exp.6.req.4, op.exp.6.req.5 · REF: op.exp.6.r1, op.exp.6.r2, op.exp.6.r3, op.exp.6.r4 | code.dependencies (heurístico, media), infra.dockerfile (heurístico, media) | No cumple |
| `op.exp.7` | Gestión de incidentes | op / Explotación | No concluyente | REQ: op.exp.7.r1.req.1, op.exp.7.r2.req.1, op.exp.7.r2.req.2, op.exp.7.r2.req.3, op.exp.7.r2.req.4, op.exp.7.r2.req.4.a, op.exp.7.r2.req.4.b, op.exp.7.r2.req.4.c, op.exp.7.r3.req.1, op.exp.7.r3.req.2, op.exp.7.req.1, op.exp.7.req.2 · REF: op.exp.7.r1, op.exp.7.r2, op.exp.7.r3 | — | Parcial |
| `op.exp.8` | Registro de la actividad | op / Explotación | Incumplimiento demostrado | REQ: op.exp.8.r1.req.1, op.exp.8.r2.req.1, op.exp.8.r3.req.1, op.exp.8.r4.req.1, op.exp.8.r5.req.1, op.exp.8.r5.req.2, op.exp.8.req.1, op.exp.8.req.2 · REF: op.exp.8.r1, op.exp.8.r2, op.exp.8.r3, op.exp.8.r4, op.exp.8.r5 | code.logging (heurístico, media) | No cumple |
| `op.exp.9` | Registro de la gestión de incidentes | op / Explotación | No concluyente | REQ: op.exp.9.req.1, op.exp.9.req.2, op.exp.9.req.3 | — | Parcial |
| `op.exp.10` | Protección de claves criptográficas | op / Explotación | Incumplimiento demostrado | REQ: op.exp.10.r1.req.1, op.exp.10.req.1, op.exp.10.req.1.1, op.exp.10.req.1.2, op.exp.10.req.1.3, op.exp.10.req.1.4, op.exp.10.req.1.5, op.exp.10.req.2, op.exp.10.req.3 · REF: op.exp.10.r1 | code.logging (heurístico, media), code.secrets (heurístico, media), infra.compose (heurístico, media), infra.dockerfile (heurístico, media) | No cumple |
| `op.ext.1` | Contratación y acuerdos de nivel de servicio | op / Recursos externos | No comprobado | REQ: op.ext.1.req.1 | — | No evaluable |
| `op.ext.2` | Gestión diaria | op / Recursos externos | No comprobado | REQ: op.ext.2.req.1, op.ext.2.req.2 | — | No evaluable |
| `op.ext.3` | Protección de la cadena de suministro | op / Recursos externos | No concluyente | REQ: op.ext.3.req.1, op.ext.3.req.2, op.ext.3.req.3 | — | Parcial |
| `op.ext.4` | Interconexión de sistemas | op / Recursos externos | No comprobado | REQ: op.ext.4.r1.req.1, op.ext.4.req.1, op.ext.4.req.2 · REF: op.ext.4.r1 | — | No evaluable |
| `op.nub.1` | Protección de servicios en la nube | op / Servicios en la nube | No concluyente | REQ: op.nub.1.r1.req.1, op.nub.1.r1.req.2, op.nub.1.r2.req.1, op.nub.1.req.1, op.nub.1.req.2, op.nub.1.req.2.a, op.nub.1.req.2.b, op.nub.1.req.2.c, op.nub.1.req.2.d · REF: op.nub.1.r1, op.nub.1.r2 | — | Parcial |
| `op.cont.1` | Análisis de impacto | op / Continuidad del servicio | No comprobado | REQ: op.cont.1.req.1 | — | No evaluable |
| `op.cont.2` | Plan de continuidad | op / Continuidad del servicio | No comprobado | REQ: op.cont.2.req.1, op.cont.2.req.2, op.cont.2.req.3, op.cont.2.req.4, op.cont.2.req.5 | — | No evaluable |
| `op.cont.3` | Pruebas periódicas | op / Continuidad del servicio | No comprobado | REQ: op.cont.3.req.1 | — | No evaluable |
| `op.cont.4` | Medios alternativos | op / Continuidad del servicio | No concluyente | REQ: op.cont.4.req.1, op.cont.4.req.1.a, op.cont.4.req.1.b, op.cont.4.req.1.c, op.cont.4.req.1.d, op.cont.4.req.1.e, op.cont.4.req.2, op.cont.4.req.3 | — | Parcial |
| `op.mon.1` | Detección de intrusión | op / Monitorización del sistema | Incumplimiento demostrado | REQ: op.mon.1.r1.req.1, op.mon.1.r2.req.1, op.mon.1.req.1 · REF: op.mon.1.r1, op.mon.1.r2 | — | No cumple |
| `op.mon.2` | Sistema de métricas | op / Monitorización del sistema | No concluyente | REQ: op.mon.2.r1.req.1, op.mon.2.r2.req.1, op.mon.2.req.1 · REF: op.mon.2.r1, op.mon.2.r2 | — | Parcial |
| `op.mon.3` | Vigilancia | op / Monitorización del sistema | No concluyente | REQ: op.mon.3.r1.req.1, op.mon.3.r2.req.1, op.mon.3.r3.req.1, op.mon.3.r3.req.2, op.mon.3.r4.req.1, op.mon.3.r5.req.1, op.mon.3.r5.req.2, op.mon.3.r6.req.1, op.mon.3.r6.req.2, op.mon.3.r6.req.3, op.mon.3.req.1 · REF: op.mon.3.r1, op.mon.3.r2, op.mon.3.r3, op.mon.3.r4, op.mon.3.r5, op.mon.3.r6 | — | Parcial |
| `mp.if.1` | Áreas separadas y con control de acceso | mp / Protección de las instalaciones e infraestructuras | No comprobado | REQ: mp.if.1.req.1, mp.if.1.req.2 | — | No evaluable |
| `mp.if.2` | Identificación de las personas | mp / Protección de las instalaciones e infraestructuras | No comprobado | REQ: mp.if.2.req.1 | — | No evaluable |
| `mp.if.3` | Acondicionamiento de los locales | mp / Protección de las instalaciones e infraestructuras | No comprobado | REQ: mp.if.3.req.1, mp.if.3.req.2, mp.if.3.req.3 | — | No evaluable |
| `mp.if.4` | Energía eléctrica | mp / Protección de las instalaciones e infraestructuras | No comprobado | REQ: mp.if.4.r1.req.1, mp.if.4.req.1 · REF: mp.if.4.r1 | — | No evaluable |
| `mp.if.5` | Protección frente a incendios. | mp / Protección de las instalaciones e infraestructuras | No comprobado | REQ: mp.if.5.req.1 | — | No evaluable |
| `mp.if.6` | Protección frente a inundaciones. | mp / Protección de las instalaciones e infraestructuras | No comprobado | REQ: mp.if.6.req.1 | — | No evaluable |
| `mp.if.7` | Registro de entrada y salida de equipamiento. | mp / Protección de las instalaciones e infraestructuras | No comprobado | REQ: mp.if.7.req.1 | — | No evaluable |
| `mp.per.1` | Caracterización del puesto de trabajo | mp / Gestión del personal | No comprobado | REQ: mp.per.1.req.1, mp.per.1.req.2 | — | No evaluable |
| `mp.per.2` | Deberes y obligaciones | mp / Gestión del personal | No comprobado | REQ: mp.per.2.r1.req.1, mp.per.2.req.1, mp.per.2.req.2, mp.per.2.req.3, mp.per.2.req.4, mp.per.2.req.4.1, mp.per.2.req.4.2 · REF: mp.per.2.r1 | — | No evaluable |
| `mp.per.3` | Concienciación | mp / Gestión del personal | No comprobado | REQ: mp.per.3.req.1, mp.per.3.req.2, mp.per.3.req.3 | — | No evaluable |
| `mp.per.4` | Formación | mp / Gestión del personal | No comprobado | REQ: mp.per.4.req.1, mp.per.4.req.1.a, mp.per.4.req.1.b, mp.per.4.req.1.c | — | No evaluable |
| `mp.eq.1` | Puesto de trabajo despejado | mp / Protección de los equipos | No comprobado | REQ: mp.eq.1.r1.req.1, mp.eq.1.req.1 · REF: mp.eq.1.r1 | — | No evaluable |
| `mp.eq.2` | Bloqueo de puesto de trabajo | mp / Protección de los equipos | No comprobado | REQ: mp.eq.2.r1.req.1, mp.eq.2.req.1 · REF: mp.eq.2.r1 | — | No evaluable |
| `mp.eq.3` | Protección de dispositivos portátiles | mp / Protección de los equipos | No comprobado | REQ: mp.eq.3.r1.req.1, mp.eq.3.r2.req.1, mp.eq.3.req.1, mp.eq.3.req.2, mp.eq.3.req.3, mp.eq.3.req.4 · REF: mp.eq.3.r1, mp.eq.3.r2 | — | No evaluable |
| `mp.eq.4` | Otros dispositivos conectados a la red | mp / Protección de los equipos | No comprobado | REQ: mp.eq.4.r1.req.1, mp.eq.4.req.1, mp.eq.4.req.2 · REF: mp.eq.4.r1 | — | No evaluable |
| `mp.com.1` | Perímetro seguro | mp / Protección de las comunicaciones | Incumplimiento demostrado | REQ: mp.com.1.req.1, mp.com.1.req.2 | infra.compose (heurístico, media), infra.terraform (heurístico, media) | No cumple |
| `mp.com.2` | Protección de la confidencialidad | mp / Protección de las comunicaciones | Incumplimiento demostrado | REQ: mp.com.2.r1.req.1, mp.com.2.r2.req.1, mp.com.2.r3.req.1, mp.com.2.req.1 · REF: mp.com.2.r1, mp.com.2.r2, mp.com.2.r3 | code.crypto (heurístico, media) | No cumple |
| `mp.com.3` | Protección de la integridad y de la autenticidad | mp / Protección de las comunicaciones | Incumplimiento demostrado | REQ: mp.com.3.r1.req.1, mp.com.3.r2.req.1, mp.com.3.r3.req.1, mp.com.3.r4.req.1, mp.com.3.req.1, mp.com.3.req.2, mp.com.3.req.2.a, mp.com.3.req.2.b, mp.com.3.req.2.c, mp.com.3.req.3 · REF: mp.com.3.r1, mp.com.3.r2, mp.com.3.r3, mp.com.3.r4 | code.crypto (heurístico, media) | No cumple |
| `mp.com.4` | Separación de flujos de información en la red | mp / Protección de las comunicaciones | No concluyente | REQ: mp.com.4.r2.req.1, mp.com.4.r3.req.1, mp.com.4.r4.req.1, mp.com.4.r4.req.2, mp.com.4.req.1, mp.com.4.req.2 · REF: mp.com.4.r2, mp.com.4.r3, mp.com.4.r4 | — | Parcial |
| `mp.si.1` | Marcado de soportes | mp / Protección de los soportes de información | No comprobado | REQ: mp.si.1.req.1 | — | No evaluable |
| `mp.si.2` | Criptografía | mp / Protección de los soportes de información | Incumplimiento demostrado | REQ: mp.si.2.r1.req.1, mp.si.2.r2.req.1, mp.si.2.req.1, mp.si.2.req.2 · REF: mp.si.2.r1, mp.si.2.r2 | code.crypto (heurístico, media), code.logging (heurístico, media), code.secrets (heurístico, media), infra.compose (heurístico, media), infra.dockerfile (heurístico, media) | No cumple |
| `mp.si.3` | Custodia | mp / Protección de los soportes de información | No comprobado | REQ: mp.si.3.req.1, mp.si.3.req.2 | — | No evaluable |
| `mp.si.4` | Transporte | mp / Protección de los soportes de información | No comprobado | REQ: mp.si.4.req.1, mp.si.4.req.2, mp.si.4.req.3, mp.si.4.req.4 | — | No evaluable |
| `mp.si.5` | Borrado y destrucción | mp / Protección de los soportes de información | No comprobado | REQ: mp.si.5.r1.req.1, mp.si.5.req.1 · REF: mp.si.5.r1 | — | No evaluable |
| `mp.sw.1` | Desarrollo de aplicaciones | mp / Protección de las aplicaciones informáticas | Incumplimiento demostrado | REQ: mp.sw.1.r1.req.1, mp.sw.1.r2.req.1, mp.sw.1.r2.req.1.a, mp.sw.1.r2.req.1.b, mp.sw.1.r2.req.1.c, mp.sw.1.r2.req.1.d, mp.sw.1.r3.req.1, mp.sw.1.r3.req.1.a, mp.sw.1.r3.req.1.b, mp.sw.1.r3.req.1.c, mp.sw.1.r4.req.1, mp.sw.1.req.1 · REF: mp.sw.1.r1, mp.sw.1.r2, mp.sw.1.r3, mp.sw.1.r4 | code.sast (heurístico, media) | No cumple |
| `mp.sw.2` | Aceptación y puesta en servicio | mp / Protección de las aplicaciones informáticas | No concluyente | REQ: mp.sw.2.r1.req.1, mp.sw.2.req.1, mp.sw.2.req.1.a, mp.sw.2.req.1.b · REF: mp.sw.2.r1 | — | Parcial |
| `mp.info.1` | Datos personales | mp / Protección de la información | No concluyente | REQ: mp.info.1.req.1 | — | Parcial |
| `mp.info.2` | Calificación de la información | mp / Protección de la información | Incumplimiento demostrado | REQ: mp.info.2.req.1, mp.info.2.req.2, mp.info.2.req.3, mp.info.2.req.4, mp.info.2.req.5 | — | No cumple |
| `mp.info.3` | Firma electrónica | mp / Protección de la información | No comprobado | REQ: mp.info.3.r1.req.1, mp.info.3.r2.req.1, mp.info.3.r3.req.1, mp.info.3.r4.req.1, mp.info.3.req.1 · REF: mp.info.3.r1, mp.info.3.r2, mp.info.3.r3, mp.info.3.r4 | — | No evaluable |
| `mp.info.4` | Sellos de tiempo | mp / Protección de la información | No comprobado | REQ: mp.info.4.req.1, mp.info.4.req.2, mp.info.4.req.3, mp.info.4.req.4 | — | No evaluable |
| `mp.info.5` | Limpieza de documentos | mp / Protección de la información | No comprobado | REQ: mp.info.5.req.1 | — | No evaluable |
| `mp.info.6` | Copias de seguridad | mp / Protección de la información | No detectado | REQ: mp.info.6.r1.req.1, mp.info.6.r2.req.1, mp.info.6.req.1, mp.info.6.req.2, mp.info.6.req.2.a, mp.info.6.req.2.b, mp.info.6.req.2.c, mp.info.6.req.2.d · REF: mp.info.6.r1, mp.info.6.r2 | infra.backup (heurístico, media) | Parcial |
| `mp.s.1` | Protección del correo electrónico | mp / Protección de los servicios | No comprobado | REQ: mp.s.1.req.1, mp.s.1.req.2, mp.s.1.req.3, mp.s.1.req.4, mp.s.1.req.5, mp.s.1.req.6, mp.s.1.req.7, mp.s.1.req.grupo.items.1, mp.s.1.req.grupo.items.2, mp.s.1.req.grupo.items.3 | — | No evaluable |
| `mp.s.2` | Protección de servicios y aplicaciones web | mp / Protección de los servicios | Incumplimiento demostrado | REQ: mp.s.2.r2.req.1, mp.s.2.r2.req.2, mp.s.2.r2.req.3, mp.s.2.r3.req.1, mp.s.2.req.1, mp.s.2.req.1.a, mp.s.2.req.1.b, mp.s.2.req.1.c, mp.s.2.req.1.d, mp.s.2.req.2, mp.s.2.req.3 · REF: mp.s.2.r2, mp.s.2.r3 | — | No cumple |
| `mp.s.3` | Protección de la navegación web | mp / Protección de los servicios | No comprobado | REQ: mp.s.3.r1.req.1, mp.s.3.r1.req.2, mp.s.3.r1.req.3, mp.s.3.req.1, mp.s.3.req.2, mp.s.3.req.3, mp.s.3.req.4, mp.s.3.req.5, mp.s.3.req.6, mp.s.3.req.7 · REF: mp.s.3.r1 | — | No evaluable |
| `mp.s.4` | Protección frente a la denegación de servicio | mp / Protección de los servicios | Incumplimiento demostrado | REQ: mp.s.4.r1.req.1, mp.s.4.r1.req.2, mp.s.4.req.1, mp.s.4.req.2 · REF: mp.s.4.r1 | infra.compose (heurístico, media), infra.terraform (heurístico, media) | No cumple |

## No conformidades

### `op.pl.1` — Análisis de riesgos (Parcial)

- **Justificación:** A STRIDE threat model exists with owner and data-flow diagrams (assets/threats), which partially addresses asset/threat identification, but there is no formal ENS risk analysis mapping safeguards and residual risks.
- **Evidencia:**
  - `threat-model.json:4` (file_line): Threat model with declared owner ('Björn Kimminich') and STRIDE diagrams.
  - `threat-model.json:1` (file_line): Threat model has summary/detail structure; no residual-risk or safeguards section.

### `op.pl.2` — Arquitectura de seguridad (Parcial)

- **Justificación:** Some architecture documentation and network segmentation exist (VPC/subnets/security groups/ALB in Terraform, threat-model data-flow diagrams), but there is no ENS security architecture doc with lines-of-defence, interconnection points or authentication scheme description.
- **Evidencia:**
  - `terraform/networking.tf:6` (file_line): VPC/subnets/security groups/ALB define network architecture.
  - `threat-model.json:1` (file_line): Data-flow/STRIDE diagrams document the system at a high level only.

### `op.pl.3` — Adquisición de nuevos componentes (Parcial)

- **Justificación:** Automated dependency updates and locked dependencies exist, giving some procurement/component control, but no process ties component acquisition to risk-analysis conclusions, security architecture, training or funding.
- **Evidencia:**
  - `.dependabot/config.yml:1` (config): Automated dependency update configuration for javascript package managers.
  - `package.json:1` (file_line): Dependencies declared/locked; no acquisition process documentation.

### `op.pl.4` — Dimensionamiento / gestión de la capacidad (Parcial)

- **Justificación:** Resource sizing is defined (ECS task CPU/memory, desired count, compose memory limits, subnet layout), partially covering processing/storage capacity, but no formal capacity-management analysis across personnel/communications/facilities dimensions.
- **Evidencia:**
  - `terraform/variables.tf:31` (file_line): task_cpu/task_memory variables define compute sizing.
  - `infrastructure/docker-compose.yml:38` (file_line): Compose deploy resources limit memory to 512M.

### `op.pl.5` — Componentes certificados (No cumple)

- **Justificación:** No evidence of selecting CCN-CPSTIC-qualified/certified products or Article 19-certified components. The stack uses standard upstream images (nginx/redis/mongo) and npm packages with no certification reference.
- **Evidencia:**
  - `infrastructure/docker-compose.yml:4` (file_line): nginx:1.28.0-alpine upstream image, not a CPSTIC-listed product.
  - `infrastructure/docker-compose.yml:59` (file_line): mongo:4.4.29 upstream image, no certification evidence.

### `op.acc.1` — Identificación (Parcial)

- **Justificación:** Accounts have unique identifiers (UserModel id/email) and distinct roles (customer/deluxe/accounting/admin), partially satisfying identification, but there is no ENS-grade identity management, account-disable lifecycle or retention period.
- **Evidencia:**
  - `models/user.ts:76` (file_line): Role field constrained to customer/deluxe/accounting/admin.
  - `models/user.ts:70` (file_line): Per-user credentials/password field define unique accounts.

### `op.acc.2` — Requisitos de acceso (No cumple)

- **Justificación:** Access-control enforcement is intentionally broken: CORS allows everything, an authorization middleware on product modification is commented out, and directory/file listing is exposed. Access to resources is not reliably restricted to authorised entities.
- **Evidencia:**
  - `server.ts:398` (file_line): PUT /api/Products authorization intentionally commented out (changeProductChallenge).
  - `server.ts:184` (file_line): app.use(cors()) allows all origins per the 'Allow everything!' comment.
  - `server.ts:290` (file_line): Public /ftp directory listing and file download exposed.

### `op.acc.4` — Proceso de gestión de derechos de acceso (No cumple)

- **Justificación:** Roles exist but least-privilege and periodic access review are not implemented; privilege escalation and broken access control are intentional challenges, and some destructive endpoints deny all while others are deliberately left open.
- **Evidencia:**
  - `server.ts:394` (file_line): PUT/DELETE /api/Users/:id denyAll, yet other endpoints are intentionally unguarded.
  - `models/user.ts:80` (file_line): Role whitelist exists but access rights are not enforced per least privilege.

### `op.acc.5` — Mecanismo de autenticación (usuarios externos) (No cumple)

- **Justificación:** External authentication is intentionally weak: login uses string-concatenated SQL, a default weak admin credential (admin123) is a known challenge, and rate limiting is applied only to reset-password, not login (no attempt limiting/lockout).
- **Evidencia:**
  - `routes/login.ts:34` (file_line): Login builds SQL by string concatenation (SQLi / loginAdmin challenge).
  - `routes/login.ts:59` (file_line): Known weak admin credential admin123 is a challenge trigger.
  - `server.ts:371` (file_line): Rate limiting only on /rest/user/reset-password; no login attempt limiting.

### `op.acc.6` — Mecanismo de autenticación (usuarios de la organización) (No cumple)

- **Justificación:** Organisation-user authentication lacks credential lifecycle controls: weak/default passwords are intentional challenges, no rotation policy exists, and lockout/attempt-limiting for internal users is absent.
- **Evidencia:**
  - `models/user.ts:73` (file_line): Password stored via security.hash but weak-password challenge is intentional.
  - `routes/login.ts:34` (file_line): Internal login shares the same weak SQL-concatenated authentication path.

### `op.exp.1` — Inventario de activos (Parcial)

- **Justificación:** A CycloneDX SBOM is generated at build time, partially covering a software-component inventory, but there is no complete asset inventory identifying every system element and its responsible owner.
- **Evidencia:**
  - `Dockerfile:20` (file_line): npm run sbom generates a CycloneDX SBOM (bom.json).
  - `package.json:77` (config): sbom script: cyclonedx-npm --output-format=JSON.

### `op.exp.2` — Configuración de seguridad (No cumple)

- **Justificación:** Ninguna.
- **Evidencia:**
  - `juice-shop/test/smoke/Dockerfile:1` (file_line): implicit user=root

### `op.exp.3` — Gestión de la configuración de seguridad (Parcial)

- **Justificación:** Security-relevant configuration is version-controlled and schema-validated, giving partial configuration management, but there is no controlled change/authorisation process for security configuration nor guarantee of minimum-functionality/least-privilege.
- **Evidencia:**
  - `lib/startup/validateConfig.ts:54` (file_line): checkConfigSchema validates configuration against a schema.
  - `config/default.yml:1` (config): Central configuration file; no authorization/change-control metadata.

### `op.exp.4` — Mantenimiento y actualizaciones de seguridad (No cumple)

- **Justificación:** Ninguna.
- **Evidencia:**
  - `juice-shop/frontend/package.json:21` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:22` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:23` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:24` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:25` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:26` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:27` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:28` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:29` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:30` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:31` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:32` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:33` (file_line): unpinned constraint: ^6.2.5
  - `juice-shop/frontend/package.json:34` (file_line): unpinned constraint: ^6.0.2
  - `juice-shop/frontend/package.json:35` (file_line): unpinned constraint: ^6.1.2
  - `juice-shop/frontend/package.json:36` (file_line): unpinned constraint: ^6.12.0
  - `juice-shop/frontend/package.json:37` (file_line): unpinned constraint: ^1.0.0
  - `juice-shop/frontend/package.json:38` (file_line): unpinned constraint: ~1.2.30
  - `juice-shop/frontend/package.json:39` (file_line): unpinned constraint: ^5.14.0
  - `juice-shop/frontend/package.json:40` (file_line): unpinned constraint: ^5.14.0
  - `juice-shop/frontend/package.json:41` (file_line): unpinned constraint: ^5.14.0
  - `juice-shop/frontend/package.json:42` (file_line): unpinned constraint: ^17.0.0
  - `juice-shop/frontend/package.json:43` (file_line): unpinned constraint: ^17.0.0
  - `juice-shop/frontend/package.json:44` (file_line): unpinned constraint: ^0.5.8
  - `juice-shop/frontend/package.json:45` (file_line): unpinned constraint: ^21.0.5
  - `juice-shop/frontend/package.json:46` (file_line): unpinned constraint: ^1.9.3
  - `juice-shop/frontend/package.json:47` (file_line): unpinned constraint: ^6.0.2
  - `juice-shop/frontend/package.json:48` (file_line): unpinned constraint: ^3.1.1
  - `juice-shop/frontend/package.json:49` (file_line): unpinned constraint: ^5.7.2
  - `juice-shop/frontend/package.json:50` (file_line): unpinned constraint: ^6.9.2
  - `juice-shop/frontend/package.json:51` (file_line): unpinned constraint: ^2.4.1
  - `juice-shop/frontend/package.json:52` (file_line): unpinned constraint: ^4.0.0
  - `juice-shop/frontend/package.json:53` (file_line): unpinned constraint: ^4.17.21
  - `juice-shop/frontend/package.json:54` (file_line): unpinned constraint: ^1.13.14
  - `juice-shop/frontend/package.json:55` (file_line): unpinned constraint: ^12.0.0
  - `juice-shop/frontend/package.json:56` (file_line): unpinned constraint: ^10.0.0
  - `juice-shop/frontend/package.json:57` (file_line): unpinned constraint: ^7.0.0
  - `juice-shop/frontend/package.json:58` (file_line): unpinned constraint: ^6.0.0
  - `juice-shop/frontend/package.json:60` (file_line): unpinned constraint: ^1.86.3
  - `juice-shop/frontend/package.json:61` (file_line): unpinned constraint: ^1.2.2
  - `juice-shop/frontend/package.json:62` (file_line): unpinned constraint: ^4.8.4
  - `juice-shop/frontend/package.json:63` (file_line): unpinned constraint: ^1.1.0
  - `juice-shop/frontend/package.json:64` (file_line): unpinned constraint: ^2.5.0
  - `juice-shop/frontend/package.json:65` (file_line): unpinned constraint: ~6.0.3
  - `juice-shop/frontend/package.json:66` (file_line): unpinned constraint: ~0.15.0
  - `juice-shop/frontend/package.json:69` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:71` (file_line): unpinned constraint: ^4.17.9
  - `juice-shop/frontend/package.json:72` (file_line): unpinned constraint: ^2.2.1
  - `juice-shop/frontend/package.json:73` (file_line): unpinned constraint: ^26.0.1
  - `juice-shop/frontend/package.json:74` (file_line): unpinned constraint: ^1.4.33
  - `juice-shop/frontend/package.json:75` (file_line): unpinned constraint: ^4.1.2
  - `juice-shop/frontend/package.json:76` (file_line): unpinned constraint: ^22.0.0
  - `juice-shop/frontend/package.json:77` (file_line): unpinned constraint: ^0.7.0
  - `juice-shop/frontend/package.json:78` (file_line): unpinned constraint: ^9.33.0
  - `juice-shop/frontend/package.json:79` (file_line): unpinned constraint: ^29.0.1
  - `juice-shop/frontend/package.json:80` (file_line): unpinned constraint: ^16.10.0
  - `juice-shop/frontend/package.json:81` (file_line): unpinned constraint: ^12.1.0
  - `juice-shop/frontend/package.json:82` (file_line): unpinned constraint: ^6.0.0
  - `juice-shop/frontend/package.json:83` (file_line): unpinned constraint: ^8.42.0
  - `juice-shop/frontend/package.json:84` (file_line): unpinned constraint: ^4.1.1
  - `juice-shop/package.json:94` (file_line): unpinned constraint: ^2.0.35
  - `juice-shop/package.json:95` (file_line): unpinned constraint: ^5.2.9
  - `juice-shop/package.json:96` (file_line): unpinned constraint: ^6.0.116
  - `juice-shop/package.json:97` (file_line): unpinned constraint: ^4.0.19
  - `juice-shop/package.json:98` (file_line): unpinned constraint: ^1.20.4
  - `juice-shop/package.json:99` (file_line): unpinned constraint: ^2.0.0
  - `juice-shop/package.json:100` (file_line): unpinned constraint: ^0.12.6
  - `juice-shop/package.json:102` (file_line): unpinned constraint: ^1.8.1
  - `juice-shop/package.json:103` (file_line): unpinned constraint: ^3.3.12
  - `juice-shop/package.json:104` (file_line): unpinned constraint: ^1.4.7
  - `juice-shop/package.json:105` (file_line): unpinned constraint: ^3.1.1
  - `juice-shop/package.json:106` (file_line): unpinned constraint: ^2.8.5
  - `juice-shop/package.json:107` (file_line): unpinned constraint: ^8.0.0
  - `juice-shop/package.json:108` (file_line): unpinned constraint: ^1.5.1
  - `juice-shop/package.json:109` (file_line): unpinned constraint: ^6.16.0
  - `juice-shop/package.json:110` (file_line): unpinned constraint: ^4.22.1
  - `juice-shop/package.json:111` (file_line): unpinned constraint: ^1.3.2
  - `juice-shop/package.json:113` (file_line): unpinned constraint: ^7.5.1
  - `juice-shop/package.json:114` (file_line): unpinned constraint: ^0.5.0
  - `juice-shop/package.json:115` (file_line): unpinned constraint: ^2.0.0
  - `juice-shop/package.json:116` (file_line): unpinned constraint: ^0.6.0
  - `juice-shop/package.json:117` (file_line): unpinned constraint: ^1.0.0
  - `juice-shop/package.json:118` (file_line): unpinned constraint: ^16.5.4
  - `juice-shop/package.json:119` (file_line): unpinned constraint: ^1.2.2
  - `juice-shop/package.json:120` (file_line): unpinned constraint: ^9.1.0
  - `juice-shop/package.json:121` (file_line): unpinned constraint: ^10.4.5
  - `juice-shop/package.json:122` (file_line): unpinned constraint: ^4.2.11
  - `juice-shop/package.json:123` (file_line): unpinned constraint: ^2.3.0
  - `juice-shop/package.json:124` (file_line): unpinned constraint: ^4.2.0
  - `juice-shop/package.json:125` (file_line): unpinned constraint: ^4.6.0
  - `juice-shop/package.json:126` (file_line): unpinned constraint: ^1.4.0
  - `juice-shop/package.json:127` (file_line): unpinned constraint: ^0.11.1
  - `juice-shop/package.json:128` (file_line): unpinned constraint: ^3.14.0
  - `juice-shop/package.json:130` (file_line): unpinned constraint: ^0.7.1
  - `juice-shop/package.json:131` (file_line): unpinned constraint: ^0.6.11
  - `juice-shop/package.json:132` (file_line): unpinned constraint: ^1.13.14
  - `juice-shop/package.json:133` (file_line): unpinned constraint: ^0.0.2
  - `juice-shop/package.json:134` (file_line): unpinned constraint: ^1.10.0
  - `juice-shop/package.json:135` (file_line): unpinned constraint: ^2.4.0
  - `juice-shop/package.json:136` (file_line): unpinned constraint: ^1.3.3
  - `juice-shop/package.json:137` (file_line): unpinned constraint: ^2.3.0
  - `juice-shop/package.json:138` (file_line): unpinned constraint: ^13.4.0
  - `juice-shop/package.json:139` (file_line): unpinned constraint: ^0.11.0
  - `juice-shop/package.json:140` (file_line): unpinned constraint: ^2.2.0
  - `juice-shop/package.json:141` (file_line): unpinned constraint: ^15.1.3
  - `juice-shop/package.json:142` (file_line): unpinned constraint: ^8.0.2
  - `juice-shop/package.json:143` (file_line): unpinned constraint: ^3.0.3
  - `juice-shop/package.json:144` (file_line): unpinned constraint: ^1.2.2
  - `juice-shop/package.json:145` (file_line): unpinned constraint: ^1.6.3
  - `juice-shop/package.json:147` (file_line): unpinned constraint: ^7.6.3
  - `juice-shop/package.json:148` (file_line): unpinned constraint: ^6.37.3
  - `juice-shop/package.json:149` (file_line): unpinned constraint: ^1.9.1
  - `juice-shop/package.json:150` (file_line): unpinned constraint: ^4.8.4
  - `juice-shop/package.json:151` (file_line): unpinned constraint: ^5.1.7
  - `juice-shop/package.json:152` (file_line): unpinned constraint: ^1.4.0
  - `juice-shop/package.json:153` (file_line): unpinned constraint: ^5.0.1
  - `juice-shop/package.json:154` (file_line): unpinned constraint: ^0.12.3
  - `juice-shop/package.json:155` (file_line): unpinned constraint: ^3.16.0
  - `juice-shop/package.json:156` (file_line): unpinned constraint: ^0.0.2
  - `juice-shop/package.json:157` (file_line): unpinned constraint: ^4.4.3
  - `juice-shop/package.json:160` (file_line): unpinned constraint: ^2.0.0||^3.0.0||^4.00
  - `juice-shop/package.json:161` (file_line): unpinned constraint: ^9.33.0
  - `juice-shop/package.json:80` (file_line): unpinned constraint: ^1.0.2
  - `juice-shop/package.json:163` (file_line): unpinned constraint: ^0.12.3
  - `juice-shop/package.json:164` (file_line): unpinned constraint: ^1.8.1
  - `juice-shop/package.json:165` (file_line): unpinned constraint: ^3.3.5
  - `juice-shop/package.json:166` (file_line): unpinned constraint: ^1.4.10
  - `juice-shop/package.json:167` (file_line): unpinned constraint: ^2.8.19
  - `juice-shop/package.json:168` (file_line): unpinned constraint: ^6.0.6
  - `juice-shop/package.json:169` (file_line): unpinned constraint: ^7.0.1
  - `juice-shop/package.json:170` (file_line): unpinned constraint: ^8.0.5
  - `juice-shop/package.json:171` (file_line): unpinned constraint: ^1.5.3
  - `juice-shop/package.json:172` (file_line): unpinned constraint: ^0.6.5
  - `juice-shop/package.json:173` (file_line): unpinned constraint: ^4.17.25
  - `juice-shop/package.json:174` (file_line): unpinned constraint: ^6.0.4
  - `juice-shop/package.json:175` (file_line): unpinned constraint: ^9.0.13
  - `juice-shop/package.json:176` (file_line): unpinned constraint: ^7.2.0
  - `juice-shop/package.json:177` (file_line): unpinned constraint: ^4.1.9
  - `juice-shop/package.json:178` (file_line): unpinned constraint: ^0.12.0
  - `juice-shop/package.json:179` (file_line): unpinned constraint: ^3.12.10
  - `juice-shop/package.json:180` (file_line): unpinned constraint: ^8.5.9
  - `juice-shop/package.json:181` (file_line): unpinned constraint: ^3.2.10
  - `juice-shop/package.json:182` (file_line): unpinned constraint: ^4.17.14
  - `juice-shop/package.json:183` (file_line): unpinned constraint: ^1.9.9
  - `juice-shop/package.json:184` (file_line): unpinned constraint: ^1.4.12
  - `juice-shop/package.json:185` (file_line): unpinned constraint: ^26.0.1
  - `juice-shop/package.json:186` (file_line): unpinned constraint: ^2.3.4
  - `juice-shop/package.json:187` (file_line): unpinned constraint: ^0.10.6
  - `juice-shop/package.json:188` (file_line): unpinned constraint: ^2.1.4
  - `juice-shop/package.json:189` (file_line): unpinned constraint: ^2.0.10
  - `juice-shop/package.json:190` (file_line): unpinned constraint: ^1.27.2
  - `juice-shop/package.json:191` (file_line): unpinned constraint: ^7.5.8
  - `juice-shop/package.json:192` (file_line): unpinned constraint: ^4.28.20
  - `juice-shop/package.json:193` (file_line): unpinned constraint: ^1.9.4
  - `juice-shop/package.json:194` (file_line): unpinned constraint: ^7.2.0
  - `juice-shop/package.json:195` (file_line): unpinned constraint: ^4.1.6
  - `juice-shop/package.json:196` (file_line): unpinned constraint: ^0.10.10
  - `juice-shop/package.json:197` (file_line): unpinned constraint: ^5.3.0
  - `juice-shop/package.json:198` (file_line): unpinned constraint: ^15.16.0
  - `juice-shop/package.json:199` (file_line): unpinned constraint: ^9.0.0
  - `juice-shop/package.json:200` (file_line): unpinned constraint: ^9.39.4
  - `juice-shop/package.json:201` (file_line): unpinned constraint: ^0.6.0
  - `juice-shop/package.json:202` (file_line): unpinned constraint: ^17.4.0
  - `juice-shop/package.json:203` (file_line): unpinned constraint: ^0.13.0
  - `juice-shop/package.json:79` (file_line): unpinned constraint: ^15.1.0
  - `juice-shop/package.json:205` (file_line): unpinned constraint: ^4.8.4
  - `juice-shop/package.json:206` (file_line): unpinned constraint: ^7.2.2
  - `juice-shop/package.json:207` (file_line): unpinned constraint: ^4.21.0
  - `juice-shop/package.json:208` (file_line): unpinned constraint: ^6.0.3
  - `juice-shop/package.json:209` (file_line): unpinned constraint: ^8.57.1
  - `juice-shop/Dockerfile:21` (file_line): FROM gcr.io/distroless/nodejs24-debian13
  - `juice-shop/infrastructure/Dockerfile:13` (file_line): FROM base
  - `juice-shop/test/smoke/Dockerfile:1` (file_line): FROM alpine

### `op.exp.5` — Gestión de cambios (Parcial)

- **Justificación:** Change control exists via PR/branch model and CI checks (lint, tests), but there is no formal change-request registry, pre-production equivalence testing record, or risk-based approval by a Security Officer.
- **Evidencia:**
  - `CONTRIBUTING.md:14` (file_line): All PRs must be based off develop; dedicated scope required.
  - `.github/workflows/ci.yml:26` (file_line): CI lint/test jobs gate changes but no change-request registry.

### `op.exp.6` — Protección frente a código dañino (No cumple)

- **Justificación:** Ninguna.
- **Evidencia:**
  - `juice-shop/frontend/package.json:21` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:22` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:23` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:24` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:25` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:26` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:27` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:28` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:29` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:30` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:31` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:32` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:33` (file_line): unpinned constraint: ^6.2.5
  - `juice-shop/frontend/package.json:34` (file_line): unpinned constraint: ^6.0.2
  - `juice-shop/frontend/package.json:35` (file_line): unpinned constraint: ^6.1.2
  - `juice-shop/frontend/package.json:36` (file_line): unpinned constraint: ^6.12.0
  - `juice-shop/frontend/package.json:37` (file_line): unpinned constraint: ^1.0.0
  - `juice-shop/frontend/package.json:38` (file_line): unpinned constraint: ~1.2.30
  - `juice-shop/frontend/package.json:39` (file_line): unpinned constraint: ^5.14.0
  - `juice-shop/frontend/package.json:40` (file_line): unpinned constraint: ^5.14.0
  - `juice-shop/frontend/package.json:41` (file_line): unpinned constraint: ^5.14.0
  - `juice-shop/frontend/package.json:42` (file_line): unpinned constraint: ^17.0.0
  - `juice-shop/frontend/package.json:43` (file_line): unpinned constraint: ^17.0.0
  - `juice-shop/frontend/package.json:44` (file_line): unpinned constraint: ^0.5.8
  - `juice-shop/frontend/package.json:45` (file_line): unpinned constraint: ^21.0.5
  - `juice-shop/frontend/package.json:46` (file_line): unpinned constraint: ^1.9.3
  - `juice-shop/frontend/package.json:47` (file_line): unpinned constraint: ^6.0.2
  - `juice-shop/frontend/package.json:48` (file_line): unpinned constraint: ^3.1.1
  - `juice-shop/frontend/package.json:49` (file_line): unpinned constraint: ^5.7.2
  - `juice-shop/frontend/package.json:50` (file_line): unpinned constraint: ^6.9.2
  - `juice-shop/frontend/package.json:51` (file_line): unpinned constraint: ^2.4.1
  - `juice-shop/frontend/package.json:52` (file_line): unpinned constraint: ^4.0.0
  - `juice-shop/frontend/package.json:53` (file_line): unpinned constraint: ^4.17.21
  - `juice-shop/frontend/package.json:54` (file_line): unpinned constraint: ^1.13.14
  - `juice-shop/frontend/package.json:55` (file_line): unpinned constraint: ^12.0.0
  - `juice-shop/frontend/package.json:56` (file_line): unpinned constraint: ^10.0.0
  - `juice-shop/frontend/package.json:57` (file_line): unpinned constraint: ^7.0.0
  - `juice-shop/frontend/package.json:58` (file_line): unpinned constraint: ^6.0.0
  - `juice-shop/frontend/package.json:60` (file_line): unpinned constraint: ^1.86.3
  - `juice-shop/frontend/package.json:61` (file_line): unpinned constraint: ^1.2.2
  - `juice-shop/frontend/package.json:62` (file_line): unpinned constraint: ^4.8.4
  - `juice-shop/frontend/package.json:63` (file_line): unpinned constraint: ^1.1.0
  - `juice-shop/frontend/package.json:64` (file_line): unpinned constraint: ^2.5.0
  - `juice-shop/frontend/package.json:65` (file_line): unpinned constraint: ~6.0.3
  - `juice-shop/frontend/package.json:66` (file_line): unpinned constraint: ~0.15.0
  - `juice-shop/frontend/package.json:69` (file_line): unpinned constraint: ^22.0.1
  - `juice-shop/frontend/package.json:71` (file_line): unpinned constraint: ^4.17.9
  - `juice-shop/frontend/package.json:72` (file_line): unpinned constraint: ^2.2.1
  - `juice-shop/frontend/package.json:73` (file_line): unpinned constraint: ^26.0.1
  - `juice-shop/frontend/package.json:74` (file_line): unpinned constraint: ^1.4.33
  - `juice-shop/frontend/package.json:75` (file_line): unpinned constraint: ^4.1.2
  - `juice-shop/frontend/package.json:76` (file_line): unpinned constraint: ^22.0.0
  - `juice-shop/frontend/package.json:77` (file_line): unpinned constraint: ^0.7.0
  - `juice-shop/frontend/package.json:78` (file_line): unpinned constraint: ^9.33.0
  - `juice-shop/frontend/package.json:79` (file_line): unpinned constraint: ^29.0.1
  - `juice-shop/frontend/package.json:80` (file_line): unpinned constraint: ^16.10.0
  - `juice-shop/frontend/package.json:81` (file_line): unpinned constraint: ^12.1.0
  - `juice-shop/frontend/package.json:82` (file_line): unpinned constraint: ^6.0.0
  - `juice-shop/frontend/package.json:83` (file_line): unpinned constraint: ^8.42.0
  - `juice-shop/frontend/package.json:84` (file_line): unpinned constraint: ^4.1.1
  - `juice-shop/package.json:94` (file_line): unpinned constraint: ^2.0.35
  - `juice-shop/package.json:95` (file_line): unpinned constraint: ^5.2.9
  - `juice-shop/package.json:96` (file_line): unpinned constraint: ^6.0.116
  - `juice-shop/package.json:97` (file_line): unpinned constraint: ^4.0.19
  - `juice-shop/package.json:98` (file_line): unpinned constraint: ^1.20.4
  - `juice-shop/package.json:99` (file_line): unpinned constraint: ^2.0.0
  - `juice-shop/package.json:100` (file_line): unpinned constraint: ^0.12.6
  - `juice-shop/package.json:102` (file_line): unpinned constraint: ^1.8.1
  - `juice-shop/package.json:103` (file_line): unpinned constraint: ^3.3.12
  - `juice-shop/package.json:104` (file_line): unpinned constraint: ^1.4.7
  - `juice-shop/package.json:105` (file_line): unpinned constraint: ^3.1.1
  - `juice-shop/package.json:106` (file_line): unpinned constraint: ^2.8.5
  - `juice-shop/package.json:107` (file_line): unpinned constraint: ^8.0.0
  - `juice-shop/package.json:108` (file_line): unpinned constraint: ^1.5.1
  - `juice-shop/package.json:109` (file_line): unpinned constraint: ^6.16.0
  - `juice-shop/package.json:110` (file_line): unpinned constraint: ^4.22.1
  - `juice-shop/package.json:111` (file_line): unpinned constraint: ^1.3.2
  - `juice-shop/package.json:113` (file_line): unpinned constraint: ^7.5.1
  - `juice-shop/package.json:114` (file_line): unpinned constraint: ^0.5.0
  - `juice-shop/package.json:115` (file_line): unpinned constraint: ^2.0.0
  - `juice-shop/package.json:116` (file_line): unpinned constraint: ^0.6.0
  - `juice-shop/package.json:117` (file_line): unpinned constraint: ^1.0.0
  - `juice-shop/package.json:118` (file_line): unpinned constraint: ^16.5.4
  - `juice-shop/package.json:119` (file_line): unpinned constraint: ^1.2.2
  - `juice-shop/package.json:120` (file_line): unpinned constraint: ^9.1.0
  - `juice-shop/package.json:121` (file_line): unpinned constraint: ^10.4.5
  - `juice-shop/package.json:122` (file_line): unpinned constraint: ^4.2.11
  - `juice-shop/package.json:123` (file_line): unpinned constraint: ^2.3.0
  - `juice-shop/package.json:124` (file_line): unpinned constraint: ^4.2.0
  - `juice-shop/package.json:125` (file_line): unpinned constraint: ^4.6.0
  - `juice-shop/package.json:126` (file_line): unpinned constraint: ^1.4.0
  - `juice-shop/package.json:127` (file_line): unpinned constraint: ^0.11.1
  - `juice-shop/package.json:128` (file_line): unpinned constraint: ^3.14.0
  - `juice-shop/package.json:130` (file_line): unpinned constraint: ^0.7.1
  - `juice-shop/package.json:131` (file_line): unpinned constraint: ^0.6.11
  - `juice-shop/package.json:132` (file_line): unpinned constraint: ^1.13.14
  - `juice-shop/package.json:133` (file_line): unpinned constraint: ^0.0.2
  - `juice-shop/package.json:134` (file_line): unpinned constraint: ^1.10.0
  - `juice-shop/package.json:135` (file_line): unpinned constraint: ^2.4.0
  - `juice-shop/package.json:136` (file_line): unpinned constraint: ^1.3.3
  - `juice-shop/package.json:137` (file_line): unpinned constraint: ^2.3.0
  - `juice-shop/package.json:138` (file_line): unpinned constraint: ^13.4.0
  - `juice-shop/package.json:139` (file_line): unpinned constraint: ^0.11.0
  - `juice-shop/package.json:140` (file_line): unpinned constraint: ^2.2.0
  - `juice-shop/package.json:141` (file_line): unpinned constraint: ^15.1.3
  - `juice-shop/package.json:142` (file_line): unpinned constraint: ^8.0.2
  - `juice-shop/package.json:143` (file_line): unpinned constraint: ^3.0.3
  - `juice-shop/package.json:144` (file_line): unpinned constraint: ^1.2.2
  - `juice-shop/package.json:145` (file_line): unpinned constraint: ^1.6.3
  - `juice-shop/package.json:147` (file_line): unpinned constraint: ^7.6.3
  - `juice-shop/package.json:148` (file_line): unpinned constraint: ^6.37.3
  - `juice-shop/package.json:149` (file_line): unpinned constraint: ^1.9.1
  - `juice-shop/package.json:150` (file_line): unpinned constraint: ^4.8.4
  - `juice-shop/package.json:151` (file_line): unpinned constraint: ^5.1.7
  - `juice-shop/package.json:152` (file_line): unpinned constraint: ^1.4.0
  - `juice-shop/package.json:153` (file_line): unpinned constraint: ^5.0.1
  - `juice-shop/package.json:154` (file_line): unpinned constraint: ^0.12.3
  - `juice-shop/package.json:155` (file_line): unpinned constraint: ^3.16.0
  - `juice-shop/package.json:156` (file_line): unpinned constraint: ^0.0.2
  - `juice-shop/package.json:157` (file_line): unpinned constraint: ^4.4.3
  - `juice-shop/package.json:160` (file_line): unpinned constraint: ^2.0.0||^3.0.0||^4.00
  - `juice-shop/package.json:161` (file_line): unpinned constraint: ^9.33.0
  - `juice-shop/package.json:80` (file_line): unpinned constraint: ^1.0.2
  - `juice-shop/package.json:163` (file_line): unpinned constraint: ^0.12.3
  - `juice-shop/package.json:164` (file_line): unpinned constraint: ^1.8.1
  - `juice-shop/package.json:165` (file_line): unpinned constraint: ^3.3.5
  - `juice-shop/package.json:166` (file_line): unpinned constraint: ^1.4.10
  - `juice-shop/package.json:167` (file_line): unpinned constraint: ^2.8.19
  - `juice-shop/package.json:168` (file_line): unpinned constraint: ^6.0.6
  - `juice-shop/package.json:169` (file_line): unpinned constraint: ^7.0.1
  - `juice-shop/package.json:170` (file_line): unpinned constraint: ^8.0.5
  - `juice-shop/package.json:171` (file_line): unpinned constraint: ^1.5.3
  - `juice-shop/package.json:172` (file_line): unpinned constraint: ^0.6.5
  - `juice-shop/package.json:173` (file_line): unpinned constraint: ^4.17.25
  - `juice-shop/package.json:174` (file_line): unpinned constraint: ^6.0.4
  - `juice-shop/package.json:175` (file_line): unpinned constraint: ^9.0.13
  - `juice-shop/package.json:176` (file_line): unpinned constraint: ^7.2.0
  - `juice-shop/package.json:177` (file_line): unpinned constraint: ^4.1.9
  - `juice-shop/package.json:178` (file_line): unpinned constraint: ^0.12.0
  - `juice-shop/package.json:179` (file_line): unpinned constraint: ^3.12.10
  - `juice-shop/package.json:180` (file_line): unpinned constraint: ^8.5.9
  - `juice-shop/package.json:181` (file_line): unpinned constraint: ^3.2.10
  - `juice-shop/package.json:182` (file_line): unpinned constraint: ^4.17.14
  - `juice-shop/package.json:183` (file_line): unpinned constraint: ^1.9.9
  - `juice-shop/package.json:184` (file_line): unpinned constraint: ^1.4.12
  - `juice-shop/package.json:185` (file_line): unpinned constraint: ^26.0.1
  - `juice-shop/package.json:186` (file_line): unpinned constraint: ^2.3.4
  - `juice-shop/package.json:187` (file_line): unpinned constraint: ^0.10.6
  - `juice-shop/package.json:188` (file_line): unpinned constraint: ^2.1.4
  - `juice-shop/package.json:189` (file_line): unpinned constraint: ^2.0.10
  - `juice-shop/package.json:190` (file_line): unpinned constraint: ^1.27.2
  - `juice-shop/package.json:191` (file_line): unpinned constraint: ^7.5.8
  - `juice-shop/package.json:192` (file_line): unpinned constraint: ^4.28.20
  - `juice-shop/package.json:193` (file_line): unpinned constraint: ^1.9.4
  - `juice-shop/package.json:194` (file_line): unpinned constraint: ^7.2.0
  - `juice-shop/package.json:195` (file_line): unpinned constraint: ^4.1.6
  - `juice-shop/package.json:196` (file_line): unpinned constraint: ^0.10.10
  - `juice-shop/package.json:197` (file_line): unpinned constraint: ^5.3.0
  - `juice-shop/package.json:198` (file_line): unpinned constraint: ^15.16.0
  - `juice-shop/package.json:199` (file_line): unpinned constraint: ^9.0.0
  - `juice-shop/package.json:200` (file_line): unpinned constraint: ^9.39.4
  - `juice-shop/package.json:201` (file_line): unpinned constraint: ^0.6.0
  - `juice-shop/package.json:202` (file_line): unpinned constraint: ^17.4.0
  - `juice-shop/package.json:203` (file_line): unpinned constraint: ^0.13.0
  - `juice-shop/package.json:79` (file_line): unpinned constraint: ^15.1.0
  - `juice-shop/package.json:205` (file_line): unpinned constraint: ^4.8.4
  - `juice-shop/package.json:206` (file_line): unpinned constraint: ^7.2.2
  - `juice-shop/package.json:207` (file_line): unpinned constraint: ^4.21.0
  - `juice-shop/package.json:208` (file_line): unpinned constraint: ^6.0.3
  - `juice-shop/package.json:209` (file_line): unpinned constraint: ^8.57.1
  - `juice-shop/Dockerfile:21` (file_line): FROM gcr.io/distroless/nodejs24-debian13
  - `juice-shop/infrastructure/Dockerfile:13` (file_line): FROM base
  - `juice-shop/test/smoke/Dockerfile:1` (file_line): FROM alpine

### `op.exp.7` — Gestión de incidentes (Parcial)

- **Justificación:** A vulnerability-reporting policy and CSAF advisory feed exist (partial incident/weakness handling), but there is no integral incident-management process with classification and notification escalation.
- **Evidencia:**
  - `SECURITY.md:18` (file_line): Vulnerability reporting policy with contact and PGP encryption.
  - `.well-known/csaf/index.txt:1` (file_line): CSAF advisory index provides security-advisory records.

### `op.exp.8` — Registro de la actividad (No cumple)

- **Justificación:** Ninguna.
- **Evidencia:**
  - `juice-shop/data/static/codefixes/loginAdminChallenge_1.ts:1` (file_line): no logging in security module
  - `juice-shop/data/static/codefixes/loginAdminChallenge_2.ts:1` (file_line): no logging in security module
  - `juice-shop/data/static/codefixes/loginAdminChallenge_3.ts:1` (file_line): no logging in security module
  - `juice-shop/data/static/codefixes/loginAdminChallenge_4_correct.ts:1` (file_line): no logging in security module
  - `juice-shop/data/static/codefixes/loginBenderChallenge_1.ts:1` (file_line): no logging in security module
  - `juice-shop/data/static/codefixes/loginBenderChallenge_2_correct.ts:1` (file_line): no logging in security module
  - `juice-shop/data/static/codefixes/loginBenderChallenge_3.ts:1` (file_line): no logging in security module
  - `juice-shop/data/static/codefixes/loginBenderChallenge_4.ts:1` (file_line): no logging in security module
  - `juice-shop/data/static/codefixes/loginJimChallenge_1_correct.ts:1` (file_line): no logging in security module
  - `juice-shop/data/static/codefixes/loginJimChallenge_2.ts:1` (file_line): no logging in security module
  - `juice-shop/data/static/codefixes/loginJimChallenge_3.ts:1` (file_line): no logging in security module
  - `juice-shop/data/static/codefixes/loginJimChallenge_4.ts:1` (file_line): no logging in security module
  - `juice-shop/frontend/src/app/password-strength-info/password-strength-info.component.spec.ts:1` (file_line): no logging in security module
  - `juice-shop/lib/insecurity.ts:1` (file_line): no logging in security module
  - `juice-shop/models/securityAnswer.ts:1` (file_line): no logging in security module
  - `juice-shop/models/securityQuestion.ts:1` (file_line): no logging in security module
  - `juice-shop/routes/authenticatedUsers.ts:1` (file_line): no logging in security module
  - `juice-shop/routes/login.ts:1` (file_line): no logging in security module
  - `juice-shop/routes/resetPassword.ts:1` (file_line): no logging in security module
  - `juice-shop/test/server/is-docker.unit.test.ts:16` (file_line): empty catch block

### `op.exp.9` — Registro de la gestión de incidentes (Parcial)

- **Justificación:** CSAF security advisories are recorded, giving partial incident/vulnerability record keeping, but there is no register of initial/intermediate/final incident reports or legally-admissible evidence handling.
- **Evidencia:**
  - `.well-known/csaf/2024/juice-shop-sa-disclaimer.json:1` (file_line): CSAF security advisory artefact stored in repo.

### `op.exp.10` — Protección de claves criptográficas (No cumple)

- **Justificación:** Ninguna.
- **Evidencia:**
  - `juice-shop/.github/workflows/issue-compliance.yml:370` (file_line): secret in log
  - `juice-shop/.github/workflows/pr-compliance.yml:505` (file_line): secret in log
  - `juice-shop/frontend/src/hacking-instructor/helpers/helpers.ts:191` (file_line): secret in log
  - `juice-shop/routes/chat.ts:255` (file_line): secret in log
  - `juice-shop/data/static/users.yml:3` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:31` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:63` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:88` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:107` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:115` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:123` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:132` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:141` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:150` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:168` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:178` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:188` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:197` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:206` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:239` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:245` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:251` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:272` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:277` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:286` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/Services/keys.service.spec.ts:68` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/app.guard.spec.ts:46` (file_line): JSON Web Token
  - `juice-shop/frontend/src/app/forgot-password/forgot-password.component.spec.ts:126` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:72` (file_line): JSON Web Token
  - `juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:78` (file_line): JSON Web Token
  - `juice-shop/frontend/src/app/nft-unlock/nft-unlock.component.spec.ts:74` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/nft-unlock/nft-unlock.component.spec.ts:83` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/nft-unlock/nft-unlock.component.spec.ts:90` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/oauth/oauth.component.spec.ts:91` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/oauth/oauth.component.spec.ts:98` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/two-factor-auth/two-factor-auth.component.spec.ts:243` (file_line): hardcoded secret assignment
  - `juice-shop/lib/insecurity.ts:21` (file_line): PEM private key
  - `juice-shop/test/api/2fa.test.ts:42` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:66` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:85` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:104` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:123` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:141` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:156` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:182` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:214` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:240` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:257` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:266` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:291` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:317` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/address.test.ts:24` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/authenticated-users.test.ts:37` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket-item.test.ts:24` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:33` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:115` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:172` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:198` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:222` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:241` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:252` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:263` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:274` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:286` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/chat.test.ts:261` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/chat.test.ts:330` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/checkKeys.test.ts:35` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/checkKeys.test.ts:46` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/checkKeys.test.ts:57` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/checkKeys.test.ts:68` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:53` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:73` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:90` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:110` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:162` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:189` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:251` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:285` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:321` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:343` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:358` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/delivery.test.ts:28` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/delivery.test.ts:54` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/delivery.test.ts:82` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/delivery.test.ts:115` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:25` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:40` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:55` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:70` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:85` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:110` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:146` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:165` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:183` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:201` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:24` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:36` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:55` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:68` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:82` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:94` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:106` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/feedback.test.ts:117` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/feedback.test.ts:143` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:27` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:36` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:76` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:90` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:104` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:132` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:147` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:245` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:267` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/memory.test.ts:32` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/memory.test.ts:53` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/memory.test.ts:66` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/memory.test.ts:78` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/memory.test.ts:93` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:25` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:56` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:69` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:82` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:97` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:111` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:125` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/password.test.ts:28` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/password.test.ts:32` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/password.test.ts:44` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/password.test.ts:95` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/payment.test.ts:20` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/product-review.test.ts:170` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/product-review.test.ts:184` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:31` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:48` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:77` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:95` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:110` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:137` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:161` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:25` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:37` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:49` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:61` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:74` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:87` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:102` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:115` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:128` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:140` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:152` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:166` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:180` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:193` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:207` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:219` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:231` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user-profile.test.ts:21` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user-profile.test.ts:58` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:52` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:68` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:136` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:154` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:172` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:189` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:240` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:280` (file_line): JSON Web Token
  - `juice-shop/test/api/user.test.ts:289` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:304` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:318` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/administration.spec.ts:5` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/b2bOrder.spec.ts:6` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/b2bOrder.spec.ts:37` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/basket.spec.ts:4` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/basket.spec.ts:76` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/changePassword.spec.ts:6` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/changePassword.spec.ts:25` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/changePassword.spec.ts:31` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/chatbot.spec.ts:8` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/complain.spec.ts:5` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/contact.spec.ts:11` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/contact.spec.ts:47` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/dataErasure.spec.ts:3` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/dataExport.spec.ts:24` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/deluxe.spec.ts:4` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/deluxe.spec.ts:21` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/forgedJwt.spec.ts:22` (file_line): JSON Web Token
  - `juice-shop/test/cypress/e2e/forgedJwt.spec.ts:38` (file_line): JSON Web Token
  - `juice-shop/test/cypress/e2e/noSql.spec.ts:8` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/noSql.spec.ts:53` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/noSql.spec.ts:76` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/noSql.spec.ts:120` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/passwordHashLeak.spec.ts:3` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/profile.spec.ts:3` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/register.spec.ts:10` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/register.spec.ts:84` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/restApi.spec.ts:4` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/restApi.spec.ts:82` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/search.spec.ts:56` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/search.spec.ts:83` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/totpSetup.spec.ts:6` (file_line): hardcoded secret assignment
  - `juice-shop/test/server/currentUser.unit.test.ts:31` (file_line): JSON Web Token
  - `juice-shop/test/server/currentUser.unit.test.ts:34` (file_line): JSON Web Token
  - `juice-shop/test/server/preconditionValidation.unit.test.ts:80` (file_line): hardcoded secret assignment
  - `juice-shop/test/server/verify.unit.test.ts:308` (file_line): JSON Web Token
  - `juice-shop/test/server/verify.unit.test.ts:316` (file_line): JSON Web Token

### `op.ext.3` — Protección de la cadena de suministro (Parcial)

- **Justificación:** Supply-chain hygiene partially exists (Dependabot, CodeQL, SBOM generation), but there is no analysis of supply-chain incident impact, risk estimation or containment measures.
- **Evidencia:**
  - `.github/workflows/codeql-analysis.yml:1` (file_line): CodeQL security scanning of dependencies/source in CI.
  - `Dockerfile:20` (file_line): SBOM generation provides component provenance.

### `op.nub.1` — Protección de servicios en la nube (Parcial)

- **Justificación:** The system is deployable on AWS (public cloud, IaaS) via Terraform, but there is no evidence of CCN-STIC service-model conformity, pentesting, transparency, key management or data-jurisdiction requirements.
- **Evidencia:**
  - `terraform/main.tf:1` (file_line): AWS provider used for cloud deployment (ECS/EFS/ALB).
  - `terraform/variables.tf:4` (file_line): Region eu-west-1; no cloud-conformity or jurisdiction requirements documented.

### `op.cont.4` — Medios alternativos (Parcial)

- **Justificación:** Technical redundancy exists (2 ECS tasks, two AZ subnets, restart policies, transitive EFS encryption), partially covering alternate means, but there is no planned alternate facilities/personnel/communications or maximum activation time.
- **Evidencia:**
  - `terraform/variables.tf:43` (file_line): desired_count=2 (two ECS task instances).
  - `terraform/networking.tf:18` (file_line): public_subnet count spans two availability zones.
  - `infrastructure/docker-compose.yml:6` (file_line): restart: unless-stopped provides process-level resilience.

### `op.mon.1` — Detección de intrusión (No cumple)

- **Justificación:** No intrusion detection/prevention tools are deployed. Network configuration defines only security groups and an ALB; there is no WAF/IDS/IPS or equivalent detection mechanism.
- **Evidencia:**
  - `terraform/networking.tf:63` (file_line): ALB security group only; no IDS/IPS/WAF resource.
  - `infrastructure/docker-compose.yml:1` (file_line): Compose stack (nginx/app/redis/mongo) contains no intrusion-detection service.

### `op.mon.2` — Sistema de métricas (Parcial)

- **Justificación:** A Prometheus metrics endpoint and a Grafana dashboard exist, giving partial measurement, but they track application/business metrics, not ENS measure-implantation metrics or the annual report required by art. 32.
- **Evidencia:**
  - `routes/metrics.ts:84` (file_line): serveMetrics exposes prom-client registry metrics.
  - `monitoring/grafana-dashboard.json:1061` (file_line): Grafana dashboard with Technical/Business metrics, not ENS compliance metrics.

### `op.mon.3` — Vigilancia (Parcial)

- **Justificación:** Automatic event collection partially exists via morgan access logs (daily rotation, audit.json), but there is no SIEM/correlation or security-event surveillance system.
- **Evidencia:**
  - `server.ts:366` (file_line): morgan('combined') writes access logs to rotating stream.
  - `server.ts:361` (file_line): audit_file: logs/audit.json configured.
  - `lib/logger.ts:8` (file_line): winston logger outputs to console only.

### `mp.com.1` — Perímetro seguro (No cumple)

- **Justificación:** Ninguna.
- **Evidencia:**
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_1.yml:2` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_1.yml:29` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_1.yml:31` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_2.yml:2` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_2.yml:29` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_2.yml:31` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_3_correct.yml:2` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_3_correct.yml:29` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_3_correct.yml:31` (file_line): no resource limits
  - `juice-shop/docker-compose.test.yml:2` (file_line): no resource limits
  - `juice-shop/docker-compose.test.yml:6` (file_line): no resource limits
  - `juice-shop/infrastructure/docker-compose.yml:3` (file_line): no resource limits
  - `juice-shop/infrastructure/docker-compose.yml:30` (file_line): no resource limits
  - `juice-shop/infrastructure/docker-compose.yml:32` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:45` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:71` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:78` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:85` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:111` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:238` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:45` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:71` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:78` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:85` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:111` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:238` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:45` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:71` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:78` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:85` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:111` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:238` (file_line): open CIDR
  - `juice-shop/infrastructure/terraform/networking.tf:46` (file_line): open CIDR
  - `juice-shop/infrastructure/terraform/networking.tf:72` (file_line): open CIDR
  - `juice-shop/infrastructure/terraform/networking.tf:79` (file_line): open CIDR
  - `juice-shop/infrastructure/terraform/networking.tf:86` (file_line): open CIDR
  - `juice-shop/infrastructure/terraform/networking.tf:112` (file_line): open CIDR
  - `juice-shop/infrastructure/terraform/networking.tf:239` (file_line): open CIDR
  - `juice-shop/terraform/networking.tf:46` (file_line): open CIDR
  - `juice-shop/terraform/networking.tf:72` (file_line): open CIDR
  - `juice-shop/terraform/networking.tf:79` (file_line): open CIDR
  - `juice-shop/terraform/networking.tf:86` (file_line): open CIDR
  - `juice-shop/terraform/networking.tf:112` (file_line): open CIDR
  - `juice-shop/terraform/networking.tf:239` (file_line): open CIDR

### `mp.com.2` — Protección de la confidencialidad (No cumple)

- **Justificación:** Ninguna.
- **Evidencia:**
  - `juice-shop/config/addo.yml:57` (file_line): http endpoint
  - `juice-shop/config/bodgeit.yml:4` (file_line): http endpoint
  - `juice-shop/config/bodgeit.yml:39` (file_line): http endpoint
  - `juice-shop/config/default.yml:76` (file_line): http endpoint
  - `juice-shop/config/default.yml:77` (file_line): http endpoint
  - `juice-shop/config/default.yml:78` (file_line): http endpoint
  - `juice-shop/config/default.yml:79` (file_line): http endpoint
  - `juice-shop/config/default.yml:87` (file_line): http endpoint
  - `juice-shop/data/datacreator.ts:86` (file_line): http endpoint
  - `juice-shop/data/datacreator.ts:173` (file_line): http endpoint
  - `juice-shop/data/static/challenges.yml:1379` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_1.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_1.ts:7` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_1.ts:9` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_2.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_2.ts:7` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_2.ts:9` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_3.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_3.ts:7` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_3.ts:9` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_4_correct.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_4_correct.ts:7` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_4_correct.ts:9` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_1.ts:5` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_1.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_1.ts:8` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_2.ts:5` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_2.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_2.ts:8` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_3_correct.ts:3` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_3_correct.ts:4` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_3_correct.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_4.ts:5` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_4.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_4.ts:8` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ar_SA.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ar_SA.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/az_AZ.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/az_AZ.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/bg_BG.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/bg_BG.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/bn_BD.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/bn_BD.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ca_ES.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ca_ES.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/cs_CZ.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/cs_CZ.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/da_DK.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/da_DK.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/de_CH.json:15` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:40` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/de_CH.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/de_CH.json:156` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:173` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:179` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:193` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:372` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:478` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:552` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:594` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:598` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:15` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:40` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:99` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:101` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/de_DE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/de_DE.json:138` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:147` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:149` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:156` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:173` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:179` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:193` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:230` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:250` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:298` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:314` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:331` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:372` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:478` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:552` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:594` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:598` (file_line): weak cipher
  - `juice-shop/data/static/i18n/el_GR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/el_GR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/en.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/en.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/es_ES.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/es_ES.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/et_EE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/et_EE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/fa_IR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/fa_IR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/fi_FI.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/fi_FI.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/fr_FR.json:7` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:69` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:73` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:100` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/fr_FR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/fr_FR.json:122` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:160` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:170` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:204` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:250` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:263` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:270` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:314` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:389` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:403` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:506` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:511` (file_line): weak cipher
  - `juice-shop/data/static/i18n/ga_IE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ga_IE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/he_IL.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/he_IL.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/hi_IN.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/hi_IN.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/hu_HU.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/hu_HU.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/id_ID.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/id_ID.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/it_IT.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/it_IT.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ja_JP.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ja_JP.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ka_GE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ka_GE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ko_KR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ko_KR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/lv_LV.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/lv_LV.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/my_MM.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/my_MM.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/nl_NL.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/nl_NL.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/no_NO.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/no_NO.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/pl_PL.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/pl_PL.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/pt_BR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/pt_BR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/pt_PT.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/pt_PT.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ro_RO.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ro_RO.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ru_RU.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ru_RU.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/si_LK.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/si_LK.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/sv_SE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/sv_SE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ta_IN.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ta_IN.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/th_TH.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/th_TH.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/tlh_AA.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/tlh_AA.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/tr_TR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/tr_TR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/uk_UA.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/uk_UA.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/zh_CN.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/zh_CN.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/zh_HK.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/zh_HK.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/zh_TW.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/zh_TW.json:110` (file_line): http endpoint
  - `juice-shop/frontend/src/app/Services/keys.service.spec.ts:68` (file_line): hardcoded key
  - `juice-shop/frontend/src/app/deluxe-user/deluxe-user.component.spec.ts:116` (file_line): http endpoint
  - `juice-shop/frontend/src/app/login/login.component.spec.ts:375` (file_line): http endpoint
  - `juice-shop/frontend/src/app/nft-unlock/nft-unlock.component.spec.ts:74` (file_line): hardcoded key
  - `juice-shop/frontend/src/app/nft-unlock/nft-unlock.component.spec.ts:83` (file_line): hardcoded key
  - `juice-shop/frontend/src/app/nft-unlock/nft-unlock.component.spec.ts:90` (file_line): hardcoded key
  - `juice-shop/frontend/src/app/order-completion/order-completion.component.spec.ts:140` (file_line): http endpoint
  - `juice-shop/frontend/src/app/order-history/order-history.component.spec.ts:53` (file_line): http endpoint
  - `juice-shop/frontend/src/app/order-history/order-history.component.spec.ts:163` (file_line): http endpoint
  - `juice-shop/frontend/src/app/score-board/components/challenge-card/challenge-card.component.spec.ts:164` (file_line): http endpoint
  - `juice-shop/frontend/src/app/score-board/components/challenge-card/challenge-card.component.spec.ts:167` (file_line): http endpoint
  - `juice-shop/frontend/src/app/score-board/components/challenge-card/challenge-card.component.spec.ts:173` (file_line): http endpoint
  - `juice-shop/frontend/src/app/score-board/components/challenge-card/challenge-card.component.spec.ts:258` (file_line): http endpoint
  - `juice-shop/frontend/src/app/score-board/components/challenge-card/challenge-card.component.spec.ts:263` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ar_SA.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/az_AZ.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/bg_BG.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/bn_BD.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ca_ES.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/cs_CZ.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/da_DK.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/de_CH.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/de_CH.json:419` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_CH.json:426` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_CH.json:427` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_CH.json:467` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_CH.json:493` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:38` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:93` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:256` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:419` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:426` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:427` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:467` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:493` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/el_GR.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/en.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/es_ES.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/et_EE.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/fa_IR.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/fi_FI.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:112` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:150` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:227` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:228` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:229` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:275` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:329` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:360` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:372` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:380` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:415` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:416` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:417` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:418` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:419` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:420` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:421` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:422` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:423` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:425` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:426` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:427` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:428` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:429` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:430` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/ga_IE.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/he_IL.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/hi_IN.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/hu_HU.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/id_ID.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/it_IT.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ja_JP.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ka_GE.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ko_KR.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/lv_LV.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/my_MM.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/nl_NL.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/no_NO.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/pl_PL.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/pt_BR.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ro_RO.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ro_RO.json:423` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/ru_RU.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/si_LK.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/sv_SE.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ta_IN.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/th_TH.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/tlh_AA.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/tr_TR.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/uk_UA.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/zh_CN.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/zh_HK.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/zh_TW.json:123` (file_line): http endpoint
  - `juice-shop/lib/insecurity.ts:21` (file_line): hardcoded key
  - `juice-shop/lib/insecurity.ts:41` (file_line): weak hash
  - `juice-shop/lib/insecurity.ts:127` (file_line): http endpoint
  - `juice-shop/lib/insecurity.ts:128` (file_line): http endpoint
  - `juice-shop/lib/insecurity.ts:130` (file_line): http endpoint
  - `juice-shop/scripts/package.mjs:121` (file_line): weak hash
  - `juice-shop/test/api/checkKeys.test.ts:35` (file_line): hardcoded key
  - `juice-shop/test/api/checkKeys.test.ts:46` (file_line): hardcoded key
  - `juice-shop/test/api/checkKeys.test.ts:57` (file_line): hardcoded key
  - `juice-shop/test/api/checkKeys.test.ts:68` (file_line): hardcoded key
  - `juice-shop/test/api/product.test.ts:104` (file_line): http endpoint
  - `juice-shop/test/api/product.test.ts:108` (file_line): http endpoint
  - `juice-shop/test/api/user-profile.test.ts:194` (file_line): http endpoint
  - `juice-shop/test/cypress/e2e/profile.spec.ts:74` (file_line): http endpoint
  - `juice-shop/test/cypress/e2e/profile.spec.ts:107` (file_line): http endpoint
  - `juice-shop/test/server/challengeUtils.unit.test.ts:114` (file_line): http endpoint
  - `juice-shop/test/server/preconditionValidation.unit.test.ts:102` (file_line): http endpoint
  - `juice-shop/test/server/preconditionValidation.unit.test.ts:103` (file_line): http endpoint
  - `juice-shop/test/server/preconditionValidation.unit.test.ts:107` (file_line): http endpoint
  - `juice-shop/test/server/redirect.unit.test.ts:42` (file_line): http endpoint
  - `juice-shop/test/server/redirect.unit.test.ts:79` (file_line): http endpoint
  - `juice-shop/test/server/system-prompt-extraction.unit.test.ts:39` (file_line): weak cipher
  - `juice-shop/test/server/system-prompt-extraction.unit.test.ts:43` (file_line): weak cipher
  - `juice-shop/test/server/utils.unit.test.ts:48` (file_line): http endpoint
  - `juice-shop/test/server/utils.unit.test.ts:52` (file_line): http endpoint
  - `juice-shop/test/server/utils.unit.test.ts:66` (file_line): http endpoint
  - `juice-shop/test/server/utils.unit.test.ts:67` (file_line): http endpoint
  - `juice-shop/test/server/utils.unit.test.ts:102` (file_line): http endpoint
  - `juice-shop/test/server/utils.unit.test.ts:324` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:84` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:93` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:102` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:111` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:121` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:130` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:139` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:148` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:157` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:166` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:252` (file_line): http endpoint

### `mp.com.3` — Protección de la integridad y de la autenticidad (No cumple)

- **Justificación:** Ninguna.
- **Evidencia:**
  - `juice-shop/config/addo.yml:57` (file_line): http endpoint
  - `juice-shop/config/bodgeit.yml:4` (file_line): http endpoint
  - `juice-shop/config/bodgeit.yml:39` (file_line): http endpoint
  - `juice-shop/config/default.yml:76` (file_line): http endpoint
  - `juice-shop/config/default.yml:77` (file_line): http endpoint
  - `juice-shop/config/default.yml:78` (file_line): http endpoint
  - `juice-shop/config/default.yml:79` (file_line): http endpoint
  - `juice-shop/config/default.yml:87` (file_line): http endpoint
  - `juice-shop/data/datacreator.ts:86` (file_line): http endpoint
  - `juice-shop/data/datacreator.ts:173` (file_line): http endpoint
  - `juice-shop/data/static/challenges.yml:1379` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_1.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_1.ts:7` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_1.ts:9` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_2.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_2.ts:7` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_2.ts:9` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_3.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_3.ts:7` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_3.ts:9` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_4_correct.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_4_correct.ts:7` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectChallenge_4_correct.ts:9` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_1.ts:5` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_1.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_1.ts:8` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_2.ts:5` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_2.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_2.ts:8` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_3_correct.ts:3` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_3_correct.ts:4` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_3_correct.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_4.ts:5` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_4.ts:6` (file_line): http endpoint
  - `juice-shop/data/static/codefixes/redirectCryptoCurrencyChallenge_4.ts:8` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ar_SA.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ar_SA.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/az_AZ.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/az_AZ.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/bg_BG.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/bg_BG.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/bn_BD.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/bn_BD.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ca_ES.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ca_ES.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/cs_CZ.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/cs_CZ.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/da_DK.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/da_DK.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/de_CH.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/de_CH.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/de_DE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/de_DE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/el_GR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/el_GR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/en.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/en.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/es_ES.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/es_ES.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/et_EE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/et_EE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/fa_IR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/fa_IR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/fi_FI.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/fi_FI.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/fr_FR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/fr_FR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ga_IE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ga_IE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/he_IL.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/he_IL.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/hi_IN.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/hi_IN.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/hu_HU.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/hu_HU.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/id_ID.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/id_ID.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/it_IT.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/it_IT.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ja_JP.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ja_JP.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ka_GE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ka_GE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ko_KR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ko_KR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/lv_LV.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/lv_LV.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/my_MM.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/my_MM.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/nl_NL.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/nl_NL.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/no_NO.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/no_NO.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/pl_PL.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/pl_PL.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/pt_BR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/pt_BR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/pt_PT.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/pt_PT.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ro_RO.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ro_RO.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ru_RU.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ru_RU.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/si_LK.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/si_LK.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/sv_SE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/sv_SE.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ta_IN.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/ta_IN.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/th_TH.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/th_TH.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/tlh_AA.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/tlh_AA.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/tr_TR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/tr_TR.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/uk_UA.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/uk_UA.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/zh_CN.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/zh_CN.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/zh_HK.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/zh_HK.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/zh_TW.json:110` (file_line): http endpoint
  - `juice-shop/data/static/i18n/zh_TW.json:110` (file_line): http endpoint
  - `juice-shop/frontend/src/app/deluxe-user/deluxe-user.component.spec.ts:116` (file_line): http endpoint
  - `juice-shop/frontend/src/app/login/login.component.spec.ts:375` (file_line): http endpoint
  - `juice-shop/frontend/src/app/order-completion/order-completion.component.spec.ts:140` (file_line): http endpoint
  - `juice-shop/frontend/src/app/order-history/order-history.component.spec.ts:53` (file_line): http endpoint
  - `juice-shop/frontend/src/app/order-history/order-history.component.spec.ts:163` (file_line): http endpoint
  - `juice-shop/frontend/src/app/score-board/components/challenge-card/challenge-card.component.spec.ts:164` (file_line): http endpoint
  - `juice-shop/frontend/src/app/score-board/components/challenge-card/challenge-card.component.spec.ts:167` (file_line): http endpoint
  - `juice-shop/frontend/src/app/score-board/components/challenge-card/challenge-card.component.spec.ts:173` (file_line): http endpoint
  - `juice-shop/frontend/src/app/score-board/components/challenge-card/challenge-card.component.spec.ts:258` (file_line): http endpoint
  - `juice-shop/frontend/src/app/score-board/components/challenge-card/challenge-card.component.spec.ts:263` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ar_SA.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/az_AZ.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/bg_BG.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/bn_BD.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ca_ES.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/cs_CZ.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/da_DK.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/de_CH.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/el_GR.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/en.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/es_ES.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/et_EE.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/fa_IR.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/fi_FI.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ga_IE.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/he_IL.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/hi_IN.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/hu_HU.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/id_ID.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/it_IT.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ja_JP.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ka_GE.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ko_KR.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/lv_LV.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/my_MM.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/nl_NL.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/no_NO.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/pl_PL.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/pt_BR.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ro_RO.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ru_RU.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/si_LK.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/sv_SE.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/ta_IN.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/th_TH.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/tlh_AA.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/tr_TR.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/uk_UA.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/zh_CN.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/zh_HK.json:123` (file_line): http endpoint
  - `juice-shop/frontend/src/assets/i18n/zh_TW.json:123` (file_line): http endpoint
  - `juice-shop/lib/insecurity.ts:127` (file_line): http endpoint
  - `juice-shop/lib/insecurity.ts:128` (file_line): http endpoint
  - `juice-shop/lib/insecurity.ts:130` (file_line): http endpoint
  - `juice-shop/test/api/product.test.ts:104` (file_line): http endpoint
  - `juice-shop/test/api/product.test.ts:108` (file_line): http endpoint
  - `juice-shop/test/api/user-profile.test.ts:194` (file_line): http endpoint
  - `juice-shop/test/cypress/e2e/profile.spec.ts:74` (file_line): http endpoint
  - `juice-shop/test/cypress/e2e/profile.spec.ts:107` (file_line): http endpoint
  - `juice-shop/test/server/challengeUtils.unit.test.ts:114` (file_line): http endpoint
  - `juice-shop/test/server/preconditionValidation.unit.test.ts:102` (file_line): http endpoint
  - `juice-shop/test/server/preconditionValidation.unit.test.ts:103` (file_line): http endpoint
  - `juice-shop/test/server/preconditionValidation.unit.test.ts:107` (file_line): http endpoint
  - `juice-shop/test/server/redirect.unit.test.ts:42` (file_line): http endpoint
  - `juice-shop/test/server/redirect.unit.test.ts:79` (file_line): http endpoint
  - `juice-shop/test/server/utils.unit.test.ts:48` (file_line): http endpoint
  - `juice-shop/test/server/utils.unit.test.ts:52` (file_line): http endpoint
  - `juice-shop/test/server/utils.unit.test.ts:66` (file_line): http endpoint
  - `juice-shop/test/server/utils.unit.test.ts:67` (file_line): http endpoint
  - `juice-shop/test/server/utils.unit.test.ts:102` (file_line): http endpoint
  - `juice-shop/test/server/utils.unit.test.ts:324` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:84` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:93` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:102` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:111` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:121` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:130` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:139` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:148` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:157` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:166` (file_line): http endpoint
  - `juice-shop/test/server/verify.unit.test.ts:252` (file_line): http endpoint

### `mp.com.4` — Separación de flujos de información en la red (Parcial)

- **Justificación:** Internal services are placed on a dedicated bridge network and redis/mongo are only exposed internally (not published to the host), partially separating information flows, but there is no evidence of traffic segregation or wireless segmentation policy.
- **Evidencia:**
  - `infrastructure/docker-compose.yml:82` (file_line): Dedicated juice-shop-net bridge network.
  - `infrastructure/docker-compose.yml:53` (file_line): redis uses expose (internal only), not host-published ports.
  - `infrastructure/docker-compose.yml:69` (file_line): mongo uses expose (internal only).

### `mp.si.2` — Criptografía (No cumple)

- **Justificación:** Ninguna.
- **Evidencia:**
  - `juice-shop/data/static/i18n/de_CH.json:15` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:40` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:156` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:173` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:179` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:193` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:372` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:478` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:552` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:594` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_CH.json:598` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:15` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:40` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:99` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:101` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:138` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:147` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:149` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:156` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:173` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:179` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:193` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:230` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:250` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:298` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:314` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:331` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:372` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:478` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:552` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:594` (file_line): weak cipher
  - `juice-shop/data/static/i18n/de_DE.json:598` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:7` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:69` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:73` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:100` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:122` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:160` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:170` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:204` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:250` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:263` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:270` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:314` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:389` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:403` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:506` (file_line): weak cipher
  - `juice-shop/data/static/i18n/fr_FR.json:511` (file_line): weak cipher
  - `juice-shop/frontend/src/app/Services/keys.service.spec.ts:68` (file_line): hardcoded key
  - `juice-shop/frontend/src/app/nft-unlock/nft-unlock.component.spec.ts:74` (file_line): hardcoded key
  - `juice-shop/frontend/src/app/nft-unlock/nft-unlock.component.spec.ts:83` (file_line): hardcoded key
  - `juice-shop/frontend/src/app/nft-unlock/nft-unlock.component.spec.ts:90` (file_line): hardcoded key
  - `juice-shop/frontend/src/assets/i18n/de_CH.json:419` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_CH.json:426` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_CH.json:427` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_CH.json:467` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_CH.json:493` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:38` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:93` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:256` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:419` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:426` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:427` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:467` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/de_DE.json:493` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:112` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:150` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:227` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:228` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:229` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:275` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:329` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:360` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:372` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:380` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:415` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:416` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:417` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:418` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:419` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:420` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:421` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:422` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:423` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:425` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:426` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:427` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:428` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:429` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/fr_FR.json:430` (file_line): weak cipher
  - `juice-shop/frontend/src/assets/i18n/ro_RO.json:423` (file_line): weak cipher
  - `juice-shop/lib/insecurity.ts:21` (file_line): hardcoded key
  - `juice-shop/lib/insecurity.ts:41` (file_line): weak hash
  - `juice-shop/scripts/package.mjs:121` (file_line): weak hash
  - `juice-shop/test/api/checkKeys.test.ts:35` (file_line): hardcoded key
  - `juice-shop/test/api/checkKeys.test.ts:46` (file_line): hardcoded key
  - `juice-shop/test/api/checkKeys.test.ts:57` (file_line): hardcoded key
  - `juice-shop/test/api/checkKeys.test.ts:68` (file_line): hardcoded key
  - `juice-shop/test/server/system-prompt-extraction.unit.test.ts:39` (file_line): weak cipher
  - `juice-shop/test/server/system-prompt-extraction.unit.test.ts:43` (file_line): weak cipher
  - `juice-shop/.github/workflows/issue-compliance.yml:370` (file_line): secret in log
  - `juice-shop/.github/workflows/pr-compliance.yml:505` (file_line): secret in log
  - `juice-shop/frontend/src/hacking-instructor/helpers/helpers.ts:191` (file_line): secret in log
  - `juice-shop/routes/chat.ts:255` (file_line): secret in log
  - `juice-shop/data/static/users.yml:3` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:31` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:63` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:88` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:107` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:115` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:123` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:132` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:141` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:150` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:168` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:178` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:188` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:197` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:206` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:239` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:245` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:251` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:272` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:277` (file_line): hardcoded secret assignment
  - `juice-shop/data/static/users.yml:286` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/Services/keys.service.spec.ts:68` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/app.guard.spec.ts:46` (file_line): JSON Web Token
  - `juice-shop/frontend/src/app/forgot-password/forgot-password.component.spec.ts:126` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:72` (file_line): JSON Web Token
  - `juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:78` (file_line): JSON Web Token
  - `juice-shop/frontend/src/app/nft-unlock/nft-unlock.component.spec.ts:74` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/nft-unlock/nft-unlock.component.spec.ts:83` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/nft-unlock/nft-unlock.component.spec.ts:90` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/oauth/oauth.component.spec.ts:91` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/oauth/oauth.component.spec.ts:98` (file_line): hardcoded secret assignment
  - `juice-shop/frontend/src/app/two-factor-auth/two-factor-auth.component.spec.ts:243` (file_line): hardcoded secret assignment
  - `juice-shop/lib/insecurity.ts:21` (file_line): PEM private key
  - `juice-shop/test/api/2fa.test.ts:42` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:66` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:85` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:104` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:123` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:141` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:156` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:182` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:214` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:240` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:257` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:266` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:291` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/2fa.test.ts:317` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/address.test.ts:24` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/authenticated-users.test.ts:37` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket-item.test.ts:24` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:33` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:115` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:172` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:198` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:222` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:241` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:252` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:263` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:274` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/basket.test.ts:286` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/chat.test.ts:261` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/chat.test.ts:330` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/checkKeys.test.ts:35` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/checkKeys.test.ts:46` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/checkKeys.test.ts:57` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/checkKeys.test.ts:68` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:53` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:73` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:90` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:110` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:162` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:189` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:251` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:285` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:321` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:343` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/data-export.test.ts:358` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/delivery.test.ts:28` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/delivery.test.ts:54` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/delivery.test.ts:82` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/delivery.test.ts:115` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:25` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:40` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:55` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:70` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:85` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:110` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:146` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:165` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:183` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/deluxe.test.ts:201` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:24` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:36` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:55` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:68` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:82` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:94` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/erasure-request.test.ts:106` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/feedback.test.ts:117` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/feedback.test.ts:143` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:27` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:36` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:76` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:90` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:104` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:132` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:147` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:245` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/login.test.ts:267` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/memory.test.ts:32` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/memory.test.ts:53` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/memory.test.ts:66` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/memory.test.ts:78` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/memory.test.ts:93` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:25` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:56` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:69` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:82` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:97` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:111` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/order-history.test.ts:125` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/password.test.ts:28` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/password.test.ts:32` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/password.test.ts:44` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/password.test.ts:95` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/payment.test.ts:20` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/product-review.test.ts:170` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/product-review.test.ts:184` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:31` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:48` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:77` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:95` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:110` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:137` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/profile-image-upload.test.ts:161` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:25` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:37` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:49` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:61` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:74` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:87` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:102` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:115` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:128` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:140` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:152` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:166` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:180` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:193` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:207` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:219` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/quantity.test.ts:231` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user-profile.test.ts:21` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user-profile.test.ts:58` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:52` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:68` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:136` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:154` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:172` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:189` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:240` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:280` (file_line): JSON Web Token
  - `juice-shop/test/api/user.test.ts:289` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:304` (file_line): hardcoded secret assignment
  - `juice-shop/test/api/user.test.ts:318` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/administration.spec.ts:5` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/b2bOrder.spec.ts:6` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/b2bOrder.spec.ts:37` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/basket.spec.ts:4` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/basket.spec.ts:76` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/changePassword.spec.ts:6` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/changePassword.spec.ts:25` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/changePassword.spec.ts:31` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/chatbot.spec.ts:8` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/complain.spec.ts:5` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/contact.spec.ts:11` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/contact.spec.ts:47` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/dataErasure.spec.ts:3` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/dataExport.spec.ts:24` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/deluxe.spec.ts:4` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/deluxe.spec.ts:21` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/forgedJwt.spec.ts:22` (file_line): JSON Web Token
  - `juice-shop/test/cypress/e2e/forgedJwt.spec.ts:38` (file_line): JSON Web Token
  - `juice-shop/test/cypress/e2e/noSql.spec.ts:8` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/noSql.spec.ts:53` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/noSql.spec.ts:76` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/noSql.spec.ts:120` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/passwordHashLeak.spec.ts:3` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/profile.spec.ts:3` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/register.spec.ts:10` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/register.spec.ts:84` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/restApi.spec.ts:4` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/restApi.spec.ts:82` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/search.spec.ts:56` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/search.spec.ts:83` (file_line): hardcoded secret assignment
  - `juice-shop/test/cypress/e2e/totpSetup.spec.ts:6` (file_line): hardcoded secret assignment
  - `juice-shop/test/server/currentUser.unit.test.ts:31` (file_line): JSON Web Token
  - `juice-shop/test/server/currentUser.unit.test.ts:34` (file_line): JSON Web Token
  - `juice-shop/test/server/preconditionValidation.unit.test.ts:80` (file_line): hardcoded secret assignment
  - `juice-shop/test/server/verify.unit.test.ts:308` (file_line): JSON Web Token
  - `juice-shop/test/server/verify.unit.test.ts:316` (file_line): JSON Web Token

### `mp.sw.1` — Desarrollo de aplicaciones (No cumple)

- **Justificación:** Ninguna.
- **Evidencia:**
  - `juice-shop/data/static/codefixes/dbSchemaChallenge_1.ts:5` (file_line): sql string concatenation
  - `juice-shop/lib/scripts/lintConfig.ts:22` (file_line): unsafe yaml.load
  - `juice-shop/routes/captcha.ts:22` (file_line): eval/exec
  - `juice-shop/routes/fileUpload.ts:114` (file_line): unsafe yaml.load
  - `juice-shop/routes/userProfile.ts:65` (file_line): eval/exec
  - `juice-shop/routes/vulnCodeFixes.ts:83` (file_line): unsafe yaml.load
  - `juice-shop/routes/vulnCodeSnippet.ts:90` (file_line): unsafe yaml.load
  - `juice-shop/rsn/rsnUtil.ts:135` (file_line): unsafe yaml.load
  - `juice-shop/server.ts:140` (file_line): unsafe yaml.load
  - `juice-shop/test/cypress/e2e/contact.spec.ts:267` (file_line): eval/exec

### `mp.sw.2` — Aceptación y puesta en servicio (Parcial)

- **Justificación:** Extensive automated test suites (unit/integration/e2e/smoke) provide partial acceptance testing, but no explicit security acceptance criteria or non-deterioration checks for other components are documented.
- **Evidencia:**
  - `.github/workflows/ci.yml:233` (file_line): Dedicated e2e-test job runs Cypress acceptance tests.
  - `.github/workflows/ci.yml:321` (file_line): Docker smoke test on the built image.
  - `package.json:57` (config): Test/lint scripts only; no explicit security acceptance criteria.

### `mp.info.1` — Datos personales (Parcial)

- **Justificación:** The system processes personal data and exposes data-export/erasure request endpoints, partially covering data-subject rights, but there is no documented RGPD/DPD requirement set or impact assessment.
- **Evidencia:**
  - `routes/dataErasure.ts:74` (file_line): Data-erasure request endpoint accepting user personal data.
  - `routes/privacyPolicyProof.ts:11` (file_line): Privacy-policy proof endpoint exists.
  - `config/default.yml:16` (config): privacyContactEmail configured.

### `mp.info.2` — Calificación de la información (No cumple)

- **Justificación:** No information classification levels, USO OFICIAL marking, information-owner assignment or criteria for required security level exist. Configuration and data models treat all information uniformly (no classification field).
- **Evidencia:**
  - `config/default.yml:5` (config): Application config contains no information-classification or owner metadata.
  - `models/user.ts:27` (file_line): Data model has no information-classification/security-level field.

### `mp.info.6` — Copias de seguridad (Parcial)

- **Justificación:** Ninguna.
- **Evidencia:** Sin evidencia registrada.

### `mp.s.2` — Protección de servicios y aplicaciones web (No cumple)

- **Justificación:** The web application is intentionally vulnerable: XSS protection is disabled, SQL injection is intentional, and injection/XSS/broken-access challenges are part of the design, so the web-service protection requirements are demonstrably not met.
- **Evidencia:**
  - `server.ts:189` (file_line): helmet.xssFilter() commented out ('no protection from persisted XSS').
  - `routes/login.ts:34` (file_line): Intentional SQL injection in the login query (loginAdmin/Bender/Jim challenges).
  - `data/static/challenges.yml:465` (file_line): Challenge catalogue includes XSS/injection/broken-access-control challenges.

### `mp.s.4` — Protección frente a la denegación de servicio (No cumple)

- **Justificación:** Ninguna.
- **Evidencia:**
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_1.yml:2` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_1.yml:29` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_1.yml:31` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_2.yml:2` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_2.yml:29` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_2.yml:31` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_3_correct.yml:2` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_3_correct.yml:29` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/vulnerableDockerImageChallenge_3_correct.yml:31` (file_line): no resource limits
  - `juice-shop/docker-compose.test.yml:2` (file_line): no resource limits
  - `juice-shop/docker-compose.test.yml:6` (file_line): no resource limits
  - `juice-shop/infrastructure/docker-compose.yml:3` (file_line): no resource limits
  - `juice-shop/infrastructure/docker-compose.yml:30` (file_line): no resource limits
  - `juice-shop/infrastructure/docker-compose.yml:32` (file_line): no resource limits
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:45` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:71` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:78` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:85` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:111` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_1.tf:238` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:45` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:71` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:78` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:85` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:111` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_2.tf:238` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:45` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:71` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:78` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:85` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:111` (file_line): open CIDR
  - `juice-shop/data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:238` (file_line): open CIDR
  - `juice-shop/infrastructure/terraform/networking.tf:46` (file_line): open CIDR
  - `juice-shop/infrastructure/terraform/networking.tf:72` (file_line): open CIDR
  - `juice-shop/infrastructure/terraform/networking.tf:79` (file_line): open CIDR
  - `juice-shop/infrastructure/terraform/networking.tf:86` (file_line): open CIDR
  - `juice-shop/infrastructure/terraform/networking.tf:112` (file_line): open CIDR
  - `juice-shop/infrastructure/terraform/networking.tf:239` (file_line): open CIDR
  - `juice-shop/terraform/networking.tf:46` (file_line): open CIDR
  - `juice-shop/terraform/networking.tf:72` (file_line): open CIDR
  - `juice-shop/terraform/networking.tf:79` (file_line): open CIDR
  - `juice-shop/terraform/networking.tf:86` (file_line): open CIDR
  - `juice-shop/terraform/networking.tf:112` (file_line): open CIDR
  - `juice-shop/terraform/networking.tf:239` (file_line): open CIDR

## Riesgos

_Señales de riesgo no demostrativas (por ejemplo, vulnerabilidades o dependencias sin fijar): no acreditan incumplimiento, pero deben revisarse._

_Sin señales de riesgo registradas._

## Recomendaciones

- Remediar **19** no conformidad(es) mayor(es) (no cumple): op.pl.5, op.acc.2, op.acc.4, op.acc.5, op.acc.6, op.exp.2, op.exp.4, op.exp.6, op.exp.8, op.exp.10, op.mon.1, mp.com.1, mp.com.2, mp.com.3, mp.si.2, mp.sw.1, mp.info.2, mp.s.2, mp.s.4.
- Revisar **19** medida(s) con cumplimiento parcial: op.pl.1, op.pl.2, op.pl.3, op.pl.4, op.acc.1, op.exp.1, op.exp.3, op.exp.5, op.exp.7, op.exp.9, op.ext.3, op.nub.1, op.cont.4, op.mon.2, op.mon.3, mp.com.4, mp.sw.2, mp.info.1, mp.info.6.
- Aportar evidencia documental o evaluación manual para **35** medida(s) no evaluables: org.1, org.2, org.3, org.4, op.acc.3, op.ext.1, op.ext.2, op.ext.4, op.cont.1, op.cont.2, op.cont.3, mp.if.1, mp.if.2, mp.if.3, mp.if.4, mp.if.5, mp.if.6, mp.if.7, mp.per.1, mp.per.2, mp.per.3, mp.per.4, mp.eq.1, mp.eq.2, mp.eq.3, mp.eq.4, mp.si.1, mp.si.3, mp.si.4, mp.si.5, mp.info.3, mp.info.4, mp.info.5, mp.s.1, mp.s.3.

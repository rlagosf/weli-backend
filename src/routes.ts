// src/routes/index.ts ✅ recomendado
import type { FastifyInstance } from "fastify";

import { noticiasPublicRoutes } from "./routers/noticias_public";

// Routers
import auth from "./routers/auth";
import auth_apoderado from "./routers/auth_apoderado";
import portal_apoderado from "./routers/portal_apoderado";

import usuarios from "./routers/usuarios";
import roles from "./routers/roles";

// ✅ Academias (nuevo) - NORMALIZADO default import
import academias from "./routers/academias";

import jugadores from "./routers/jugadores";
import categorias from "./routers/categorias";
import eventos from "./routers/eventos";

import medio_pago from "./routers/medio_pago";
import pagos_jugador from "./routers/pagos_jugador";
import tipo_pago from "./routers/tipo_pago";
import situacion_pago from "./routers/situacion_pago";

import comunas from "./routers/comunas";
import posiciones from "./routers/posiciones";
import estado from "./routers/estado";
import prevision_medica from "./routers/prevision_medica";
import establec_educ from "./routers/establec_educ";
import sucursales_real from "./routers/sucursales_real";
import deportes from "./routers/deportes";


import estadisticas from "./routers/estadisticas";
import convocatorias from "./routers/convocatorias";
import convocatorias_historico from "./routers/convocatorias_historico";

import admin_noticias from "./routers/admin_noticias";
import estado_noticias from "./routers/estado_noticias";

import gabriela from "./gabriela";

export async function registerRoutes(app: FastifyInstance) {
  const API_BASE = "/api";

  // ───────────────────────── Auth ─────────────────────────
  app.register(auth, { prefix: `${API_BASE}/auth` });
  app.register(auth_apoderado, { prefix: `${API_BASE}/auth-apoderado` });
  app.register(portal_apoderado, { prefix: `${API_BASE}/portal-apoderado` });

  // ───────────────────────── Core ─────────────────────────
  app.register(usuarios, { prefix: `${API_BASE}/usuarios` });
  app.register(roles, { prefix: `${API_BASE}/roles` });

  // ───────────────────────── Multi-academia ─────────────────────────
  // ✅ Si quieres SOLO SUPERADMIN (rol 3), se controla dentro del router con requireRoles([3])
  app.register(academias, { prefix: `${API_BASE}/academias` });

  // ───────────────────────── Dominio ─────────────────────────
  app.register(jugadores, { prefix: `${API_BASE}/jugadores` });
  app.register(categorias, { prefix: `${API_BASE}/categorias` });
  app.register(eventos, { prefix: `${API_BASE}/eventos` });

  // ───────────────────────── Pagos ─────────────────────────
  app.register(medio_pago, { prefix: `${API_BASE}/medio-pago` });
  app.register(pagos_jugador, { prefix: `${API_BASE}/pagos-jugador` });
  app.register(tipo_pago, { prefix: `${API_BASE}/tipo-pago` });
  app.register(situacion_pago, { prefix: `${API_BASE}/situacion-pago` });

  // ───────────────────────── Catálogos ─────────────────────────
  app.register(comunas, { prefix: `${API_BASE}/comunas` });
  app.register(posiciones, { prefix: `${API_BASE}/posiciones` });
  app.register(estado, { prefix: `${API_BASE}/estado` });
  app.register(prevision_medica, { prefix: `${API_BASE}/prevision-medica` });
  app.register(establec_educ, { prefix: `${API_BASE}/establecimientos-educ` });
  app.register(sucursales_real, { prefix: `${API_BASE}/sucursales-real` });
  app.register(deportes, { prefix: `${API_BASE}/deportes` });

  // ───────────────────────── Reportes ─────────────────────────
  app.register(estadisticas, { prefix: `${API_BASE}/estadisticas` });
  app.register(convocatorias, { prefix: `${API_BASE}/convocatorias` });
  app.register(convocatorias_historico, {
    prefix: `${API_BASE}/convocatorias-historico`,
  });

  // ───────────────────────── Noticias ─────────────────────────
  app.register(noticiasPublicRoutes, { prefix: `${API_BASE}/noticias` });
  app.register(admin_noticias, { prefix: `${API_BASE}/admin-noticias` });
  app.register(estado_noticias, { prefix: `${API_BASE}/estado-noticias` });

  // ───────────────────────── IA ─────────────────────────
  app.register(gabriela, { prefix: `${API_BASE}/gabriela` });
}

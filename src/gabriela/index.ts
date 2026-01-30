// src/gabriela/index.ts
import { FastifyInstance } from "fastify";
import routes from "./routes";

export default async function gabriela(app: FastifyInstance) {
  // Registrar rutas del módulo
  await app.register(routes);
}

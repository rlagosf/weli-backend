// src/routers/categorias.ts
import { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireRoles } from "../middlewares/authz";

const CategoriaCreateSchema = z.object({
  nombre: z.string().min(1, "nombre requerido").max(100),
});

const CategoriaUpdateSchema = z.object({
  nombre: z.string().min(1, "nombre requerido").max(100),
});

export default async function categorias(app: FastifyInstance) {
  // ✅ Regla de oro: catálogos
  const canRead = [requireAuth, requireRoles([1, 2])]; // admin + staff
  const canWrite = [requireAuth, requireRoles([1])];   // solo admin

  // Health (read: roles 1/2)
  app.get("/health", { preHandler: canRead }, async () => ({
    module: "categorias",
    status: "ready",
    timestamp: new Date().toISOString(),
  }));

  // Listar todas (read: roles 1/2)
  app.get("/", { preHandler: canRead }, async (_req, reply) => {
    try {
      const [rows] = await db.query(
        "SELECT id, nombre FROM categorias ORDER BY id ASC"
      );
      return reply.send({ ok: true, items: rows });
    } catch {
      return reply.code(500).send({
        ok: false,
        message: "Error al consultar categorías",
      });
    }
  });

  // Obtener por ID (read: roles 1/2)
  app.get("/:id", { preHandler: canRead }, async (req, reply) => {
    const id = Number((req.params as any).id);
    if (Number.isNaN(id)) {
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const [rows]: any = await db.query(
        "SELECT id, nombre FROM categorias WHERE id = ? LIMIT 1",
        [id]
      );

      if (!rows.length) {
        return reply.code(404).send({ ok: false, message: "No encontrada" });
      }

      return reply.send({ ok: true, item: rows[0] });
    } catch {
      return reply.code(500).send({
        ok: false,
        message: "Error al buscar categoría",
      });
    }
  });

  // Crear (write: solo rol 1)
  app.post("/", { preHandler: canWrite }, async (req, reply) => {
    try {
      const data = CategoriaCreateSchema.parse(req.body);

      const [result]: any = await db.query(
        "INSERT INTO categorias (nombre) VALUES (?)",
        [data.nombre]
      );

      return reply.code(201).send({
        ok: true,
        id: result.insertId,
        nombre: data.nombre,
      });
    } catch (error: any) {
      const msg =
        error?.code === "ER_DUP_ENTRY"
          ? "El nombre ya existe"
          : error?.message ?? "BAD_REQUEST";
      return reply.code(400).send({ ok: false, message: msg });
    }
  });

  // Actualizar (write: solo rol 1)
  app.put("/:id", { preHandler: canWrite }, async (req, reply) => {
    const id = Number((req.params as any).id);
    if (Number.isNaN(id)) {
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const { nombre } = CategoriaUpdateSchema.parse(req.body);

      const [result]: any = await db.query(
        "UPDATE categorias SET nombre = ? WHERE id = ?",
        [nombre, id]
      );

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrada" });
      }

      return reply.send({ ok: true, updated: { id, nombre } });
    } catch (error: any) {
      const msg =
        error?.code === "ER_DUP_ENTRY"
          ? "El nombre ya existe"
          : error?.message ?? "BAD_REQUEST";
      return reply.code(400).send({ ok: false, message: msg });
    }
  });

  // Eliminar (write: solo rol 1)
  app.delete("/:id", { preHandler: canWrite }, async (req, reply) => {
    const id = Number((req.params as any).id);
    if (Number.isNaN(id)) {
      return reply.code(400).send({ ok: false, message: "ID inválido" });
    }

    try {
      const [result]: any = await db.query(
        "DELETE FROM categorias WHERE id = ?",
        [id]
      );

      if (result.affectedRows === 0) {
        return reply.code(404).send({ ok: false, message: "No encontrada" });
      }

      return reply.send({ ok: true, deleted: id });
    } catch (error: any) {
      const msg =
        error?.code === "ER_ROW_IS_REFERENCED_2"
          ? "No se puede eliminar: está siendo usada por jugadores o estadísticas"
          : error?.message ?? "SERVER_ERROR";

      return reply.code(500).send({ ok: false, message: msg });
    }
  });
}

// src/gabriela/validators.ts
import { z } from "zod";

export const CrearCasoSchema = z
  .object({
    rut_jugador: z.number().int().nonnegative().nullable(),
    motivo: z.string().trim().max(255).nullable().optional(),
    fecha_inicio: z
      .string()
      .trim()
      .regex(/^\d{4}-\d{2}-\d{2}$/, "fecha_inicio debe ser YYYY-MM-DD")
      .nullable()
      .optional(),
  })
  .strict();

export const IdParamSchema = z.object({
  id: z.coerce.number().int().positive(),
});

export const SubirExamenSchema = z
  .object({
    id_caso: z.number().int().positive(),
    id_fuente_examen: z.number().int().positive().optional(),
    tipo_examen: z.string().trim().min(2).max(80),
    fecha_examen: z
      .string()
      .trim()
      .regex(/^\d{4}-\d{2}-\d{2}$/, "fecha_examen debe ser YYYY-MM-DD")
      .nullable()
      .optional(),
    laboratorio: z.string().trim().max(120).nullable().optional(),

    nombre_archivo: z.string().trim().max(255).nullable().optional(),
    mime: z.string().trim().min(3).max(80),

    contenido_base64: z.string().trim().min(10), // validación fuerte en services.ts
  })
  .strict();

export const ProcesarExamenParamSchema = z.object({
  id: z.coerce.number().int().positive(),
});

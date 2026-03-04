import { z } from "zod";

export const ScopeConfigSchema = z.object({
  allowedCidrs: z.array(z.string()),
  allowedDomains: z.array(z.string()).optional(),
  blockedCidrs: z.array(z.string()).default([
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
  ]),
  restrictions: z
    .object({
      allowActiveScanning: z.boolean().default(true),
      allowExploitation: z.boolean().default(false),
      allowBruteForce: z.boolean().default(false),
      maxConcurrentScans: z.number().default(5),
    })
    .optional(),
});

export type ScopeConfig = z.infer<typeof ScopeConfigSchema>;

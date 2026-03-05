import { z } from "zod";

const cidrFormat = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;

const cidrString = z
  .string()
  .refine((s) => cidrFormat.test(s), { message: "Invalid CIDR format" });

export const ScopeConfigSchema = z.object({
  allowedCidrs: z.array(cidrString),
  allowedDomains: z.array(z.string()).optional(),
  blockedCidrs: z.array(cidrString).default([
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

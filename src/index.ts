export const EXIT_CODES = {
  OK: 0,
  SANITY_FAILURE: 1,
  USAGE_ERROR: 2,
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

export interface VibesaneOptions {
  port?: number;
}

export interface VibesaneResult {
  ok: boolean;
  port: number | 'auto';
  message: string;
}

export async function runVibesane(options: VibesaneOptions = {}): Promise<VibesaneResult> {
  if (options.port !== undefined) {
    if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
      throw new RangeError(`Invalid port "${options.port}": expected integer between 1 and 65535`);
    }
  }
  const port = options.port ?? 'auto';
  return {
    ok: true,
    port,
    message: `vibesane: scanner stub (port: ${port})`,
  };
}

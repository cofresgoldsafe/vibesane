import {
  DEFAULT_PORTS,
  DEFAULT_TCP_TIMEOUT_MS,
  DEFAULT_HTTP_TIMEOUT_MS,
  assertValidPort,
  probeTcpPort,
  detectServer,
  type LoopbackHost,
  type DetectionFailureReason,
  type PortDetectorOptions,
  type TcpProbeResult,
  type PortDetectionResult,
} from './scanner/port-detector.js';

export {
  DEFAULT_PORTS,
  DEFAULT_TCP_TIMEOUT_MS,
  DEFAULT_HTTP_TIMEOUT_MS,
  assertValidPort,
  probeTcpPort,
  detectServer,
  type LoopbackHost,
  type DetectionFailureReason,
  type PortDetectorOptions,
  type TcpProbeResult,
  type PortDetectionResult,
};

export const EXIT_CODES = {
  OK: 0,
  SANITY_FAILURE: 1,
  USAGE_ERROR: 2,
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

export type VibesaneOptions = PortDetectorOptions;

export interface VibesaneResult extends PortDetectionResult {
  message: string;
}

export async function runVibesane(options: VibesaneOptions = {}): Promise<VibesaneResult> {
  const detection = await detectServer(options);
  let message: string;

  if (detection.ok) {
    const alsoSuffix =
      detection.alsoActivePorts.length > 0
        ? ` (also active: ${detection.alsoActivePorts.join(', ')})`
        : '';
    message = `vibesane: connected to ${detection.url} (${detection.elapsedMs}ms)${alsoSuffix}`;
  } else if (detection.reason === 'http_timeout') {
    const httpTimeoutMs = options.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
    const label = httpTimeoutMs % 1000 === 0 ? `${httpTimeoutMs / 1000}s` : `${httpTimeoutMs}ms`;
    message = `vibesane: port ${detection.port} accepted the connection but took >${label} to respond (still compiling?)`;
  } else if (detection.reason === 'non_http') {
    message = `vibesane: port ${detection.port} is open but did not respond to HTTP`;
  } else {
    if (detection.checkedPorts.length === 1) {
      message = `vibesane: no active server found on port ${detection.checkedPorts[0]}`;
    } else {
      message = `vibesane: no active server found on ports ${detection.checkedPorts.join(', ')}`;
    }
  }

  return {
    ...detection,
    message,
  };
}

import net from 'node:net';
import { performance } from 'node:perf_hooks';

export const DEFAULT_PORTS = [3000, 3001, 5173, 5174, 8080, 8000, 4321] as const;
export const DEFAULT_TCP_TIMEOUT_MS = 300;
export const DEFAULT_HTTP_TIMEOUT_MS = 2000;

export type LoopbackHost = '127.0.0.1' | '::1';
export type DetectionFailureReason = 'no_server' | 'non_http' | 'http_timeout';

export interface PortDetectorOptions {
  port?: number;
  ports?: readonly number[];
  tcpTimeoutMs?: number;
  httpTimeoutMs?: number;
}

export interface TcpProbeResult {
  port: number;
  open: boolean;
  host?: LoopbackHost;
  elapsedMs: number;
}

export interface PortDetectionResult {
  ok: boolean;
  port: number | null;
  host?: LoopbackHost;
  url?: string;
  statusCode?: number;
  elapsedMs: number;
  alsoActivePorts: number[];
  checkedPorts: number[];
  reason?: DetectionFailureReason;
}

export function assertValidPort(port: number): void {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new RangeError(`Invalid port "${port}": expected integer between 1 and 65535`);
  }
}

export function assertValidTimeout(ms: number, name = 'timeout'): void {
  if (typeof ms !== 'number' || !Number.isFinite(ms) || ms <= 0) {
    throw new RangeError(`Invalid ${name} "${ms}": expected positive finite number`);
  }
}

export function probeTcpPort(
  port: number,
  tcpTimeoutMs: number = DEFAULT_TCP_TIMEOUT_MS,
  signal?: AbortSignal,
): Promise<TcpProbeResult> {
  assertValidPort(port);
  assertValidTimeout(tcpTimeoutMs, 'tcpTimeoutMs');

  const startedAt = performance.now();

  return new Promise<TcpProbeResult>((resolve) => {
    if (signal?.aborted) {
      resolve({
        port,
        open: false,
        elapsedMs: Math.max(0, Math.round(performance.now() - startedAt)),
      });
      return;
    }

    let settled = false;
    let failedCount = 0;
    const hosts: readonly LoopbackHost[] = ['127.0.0.1', '::1'];
    const sockets: net.Socket[] = [];

    const onAbort = (): void => {
      finish(false);
    };

    const timer = setTimeout(() => {
      finish(false);
    }, tcpTimeoutMs);

    const cleanup = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      for (const socket of sockets) {
        socket.removeAllListeners();
        socket.destroy();
      }
    };

    const finish = (open: boolean, winningHost?: LoopbackHost): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      const elapsedMs = Math.max(0, Math.round(performance.now() - startedAt));
      if (open && winningHost) {
        resolve({ port, open: true, host: winningHost, elapsedMs });
      } else {
        resolve({ port, open: false, elapsedMs });
      }
    };

    signal?.addEventListener('abort', onAbort, { once: true });

    for (const host of hosts) {
      const socket = net.createConnection({ host, port });
      sockets.push(socket);

      socket.once('connect', () => {
        finish(true, host);
      });

      socket.once('error', () => {
        failedCount += 1;
        if (failedCount >= hosts.length) {
          finish(false);
        }
      });
    }
  });
}

export async function detectServer(
  options: PortDetectorOptions = {},
): Promise<PortDetectionResult> {
  const startedAt = performance.now();
  const tcpTimeoutMs = options.tcpTimeoutMs ?? DEFAULT_TCP_TIMEOUT_MS;
  const httpTimeoutMs = options.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
  assertValidTimeout(tcpTimeoutMs, 'tcpTimeoutMs');
  assertValidTimeout(httpTimeoutMs, 'httpTimeoutMs');

  let checkedPorts: number[];
  if (options.port !== undefined) {
    assertValidPort(options.port);
    checkedPorts = [options.port];
  } else if (options.ports !== undefined) {
    if (options.ports.length === 0) {
      throw new RangeError('ports list cannot be empty');
    }
    for (const p of options.ports) {
      assertValidPort(p);
    }
    checkedPorts = [...new Set(options.ports)];
  } else {
    checkedPorts = [...DEFAULT_PORTS];
  }

  const controllers = checkedPorts.map(() => new AbortController());
  const results: Array<TcpProbeResult | null> = new Array(checkedPorts.length).fill(null);

  let winnerIndex = -1;
  let resolveStage1!: () => void;
  const stage1Done = new Promise<void>((resolve) => {
    resolveStage1 = resolve;
  });

  let graceStarted = false;
  let graceTimer: ReturnType<typeof setTimeout> | null = null;
  let settledStage1 = false;

  const finishStage1 = (): void => {
    if (settledStage1) {
      return;
    }
    settledStage1 = true;
    if (graceTimer !== null) {
      clearTimeout(graceTimer);
      graceTimer = null;
    }
    if (winnerIndex !== -1) {
      for (let k = winnerIndex + 1; k < checkedPorts.length; k++) {
        if (results[k] === null) {
          controllers[k].abort();
        }
      }
    }
    resolveStage1();
  };

  const evaluateProgress = (): void => {
    if (settledStage1) {
      return;
    }

    if (winnerIndex === -1) {
      let candidate = -1;
      for (let i = 0; i < checkedPorts.length; i++) {
        const res = results[i];
        if (res === null) {
          break;
        }
        if (res.open) {
          candidate = i;
          break;
        }
      }

      if (candidate !== -1) {
        winnerIndex = candidate;
      } else {
        const allFinished = results.every((r) => r !== null);
        if (allFinished) {
          finishStage1();
        }
        return;
      }
    }

    const anyLowerPriorityPending = results
      .slice(winnerIndex + 1)
      .some((r) => r === null);

    if (!anyLowerPriorityPending) {
      finishStage1();
      return;
    }

    if (!graceStarted) {
      graceStarted = true;
      const graceMs = Math.min(15, Math.floor(tcpTimeoutMs / 5));
      if (graceMs <= 0) {
        finishStage1();
      } else {
        graceTimer = setTimeout(() => {
          finishStage1();
        }, graceMs);
      }
    }
  };

  const probePromises = checkedPorts.map((port, index) =>
    probeTcpPort(port, tcpTimeoutMs, controllers[index].signal).then((res) => {
      results[index] = res;
      evaluateProgress();
      return res;
    }),
  );

  await stage1Done;
  await Promise.all(probePromises);

  if (winnerIndex === -1) {
    return {
      ok: false,
      port: null,
      elapsedMs: Math.max(0, Math.round(performance.now() - startedAt)),
      alsoActivePorts: [],
      checkedPorts,
      reason: 'no_server',
    };
  }

  const winner = results[winnerIndex]!;
  const winnerPort = winner.port;
  const winnerHost = winner.host ?? '127.0.0.1';

  const alsoActivePorts: number[] = [];
  for (let k = winnerIndex + 1; k < checkedPorts.length; k++) {
    const res = results[k];
    if (res?.open) {
      alsoActivePorts.push(checkedPorts[k]);
    }
  }

  const fetchHost = winnerHost === '::1' ? '[::1]' : '127.0.0.1';
  const targetUrl = `http://${fetchHost}:${winnerPort}/`;
  const displayUrl = `http://localhost:${winnerPort}`;

  try {
    const res = await fetch(targetUrl, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(httpTimeoutMs),
    });
    await res.body?.cancel().catch(() => {});

    return {
      ok: true,
      port: winnerPort,
      host: winnerHost,
      url: displayUrl,
      statusCode: res.status,
      elapsedMs: Math.max(0, Math.round(performance.now() - startedAt)),
      alsoActivePorts,
      checkedPorts,
    };
  } catch (err: unknown) {
    const isTimeout =
      err instanceof Error &&
      (err.name === 'TimeoutError' || err.name === 'AbortError');

    return {
      ok: false,
      port: winnerPort,
      host: winnerHost,
      url: displayUrl,
      elapsedMs: Math.max(0, Math.round(performance.now() - startedAt)),
      alsoActivePorts,
      checkedPorts,
      reason: isTimeout ? 'http_timeout' : 'non_http',
    };
  }
}

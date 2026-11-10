import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { runVibesane, EXIT_CODES } from './index.js';
import { formatTerminalReport, shouldEnableColor } from './reporter/terminal-ui.js';

export interface CliIO {
  stdout: (msg: string) => void;
  stderr: (msg: string) => void;
}

const HELP_TEXT = [
  'Usage: vibesane [options]',
  '',
  'Options:',
  '  -p, --port <number>  Target local port (1-65535)',
  '      --url <url>      Target published web URL (http:// or https://)',
  '  -h, --help           Show help',
  '  -v, --version        Show version',
].join('\n');

function getVersion(): string {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
    version: string;
  };
  return pkg.version;
}

function isLoopbackHost(hostname: string): boolean {
  let host = hostname.toLowerCase();
  if (
    host === 'localhost' ||
    host === 'localhost.' ||
    host.endsWith('.localhost') ||
    host.endsWith('.localhost.')
  ) {
    return true;
  }
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
  }
  if (
    host === '0.0.0.0' ||
    host === '127.0.0.1' ||
    /^127\.\d+\.\d+\.\d+$/.test(host) ||
    host === '::1'
  ) {
    return true;
  }
  // IPv4-mapeado em IPv6 loopback (::ffff:127.x.x.x e ::ffff:7fxx:xxxx)
  if (host.startsWith('::ffff:')) {
    const rest = host.slice('::ffff:'.length);
    if (/^127\.\d+\.\d+\.\d+$/.test(rest)) {
      return true;
    }
    if (/^7f[0-9a-f]{2}:[0-9a-f]{1,4}$/i.test(rest)) {
      return true;
    }
  }
  return false;
}

export async function main(
  argv: string[] = process.argv.slice(2),
  io: Partial<CliIO> = {}
): Promise<number> {
  const stdout = io.stdout ?? ((msg: string) => process.stdout.write(`${msg}\n`));
  const stderr = io.stderr ?? ((msg: string) => process.stderr.write(`${msg}\n`));

  const stopIdx = argv.indexOf('--');
  const activeArgs = stopIdx === -1 ? argv : argv.slice(0, stopIdx);
  if (activeArgs.includes('--help') || activeArgs.includes('-h')) {
    stdout(HELP_TEXT);
    return EXIT_CODES.OK;
  }
  if (activeArgs.includes('--version') || activeArgs.includes('-v')) {
    stdout(getVersion());
    return EXIT_CODES.OK;
  }

  let values: {
    port?: string[];
    url?: string[];
    help?: boolean;
    version?: boolean;
  };

  try {
    const parsed = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        port: { type: 'string', short: 'p', multiple: true },
        url: { type: 'string', multiple: true },
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
      },
    });
    values = parsed.values;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    stderr(`vibesane: error: ${message}`);
    return EXIT_CODES.USAGE_ERROR;
  }

  if (values.help) {
    stdout(HELP_TEXT);
    return EXIT_CODES.OK;
  }

  if (values.version) {
    stdout(getVersion());
    return EXIT_CODES.OK;
  }

  if (values.port !== undefined && values.url !== undefined) {
    stderr('vibesane: error: options --url and --port cannot be used together');
    return EXIT_CODES.USAGE_ERROR;
  }

  let portNum: number | undefined;
  if (values.port !== undefined) {
    if (values.port.length > 1) {
      stderr('vibesane: error: option --port cannot be specified multiple times');
      return EXIT_CODES.USAGE_ERROR;
    }
    const rawPort = values.port[0];
    if (rawPort === undefined || !/^[1-9]\d*$/.test(rawPort)) {
      stderr(`vibesane: error: invalid port "${rawPort ?? ''}" (expected integer 1-65535)`);
      return EXIT_CODES.USAGE_ERROR;
    }
    portNum = Number(rawPort);
    if (portNum < 1 || portNum > 65535) {
      stderr(`vibesane: error: invalid port "${rawPort}" (expected integer 1-65535)`);
      return EXIT_CODES.USAGE_ERROR;
    }
  }

  let targetUrl: string | undefined;
  if (values.url !== undefined) {
    if (values.url.length > 1) {
      stderr('vibesane: error: option --url cannot be specified multiple times');
      return EXIT_CODES.USAGE_ERROR;
    }
    const rawUrl = values.url[0] ?? '';
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(rawUrl);
    } catch {
      stderr(`vibesane: error: invalid url "${rawUrl}" (malformed URL)`);
      return EXIT_CODES.USAGE_ERROR;
    }

    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      stderr(`vibesane: error: invalid url "${rawUrl}" (only http:// and https:// are supported)`);
      return EXIT_CODES.USAGE_ERROR;
    }

    if (isLoopbackHost(parsedUrl.hostname)) {
      stderr('vibesane: error: --url cannot point to localhost/loopback; use -p <port> instead');
      return EXIT_CODES.USAGE_ERROR;
    }

    targetUrl = rawUrl;
    stdout('vibesane: warning: use only on websites you own or have explicit authorization to test.');
  }

  const result = await runVibesane(
    targetUrl !== undefined
      ? { url: targetUrl }
      : portNum !== undefined
        ? { port: portNum }
        : {}
  );
  const useColor = io.stdout === undefined && shouldEnableColor();
  const output = formatTerminalReport(result, { color: useColor });
  stdout(output);
  return result.ok ? EXIT_CODES.OK : EXIT_CODES.SANITY_FAILURE;
}

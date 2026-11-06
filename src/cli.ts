import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { runVibesane, EXIT_CODES } from './index.js';

export interface CliIO {
  stdout: (msg: string) => void;
  stderr: (msg: string) => void;
}

const HELP_TEXT = [
  'Usage: vibesane [options]',
  '',
  'Options:',
  '  -p, --port <number>  Target local port (1-65535)',
  '  -h, --help           Show help',
  '  -v, --version        Show version',
].join('\n');

function getVersion(): string {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
    version: string;
  };
  return pkg.version;
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

  const result = await runVibesane(portNum !== undefined ? { port: portNum } : {});
  stdout(result.message);
  return result.ok ? EXIT_CODES.OK : EXIT_CODES.SANITY_FAILURE;
}

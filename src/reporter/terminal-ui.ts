import { styleText } from 'node:util';
import {
  AI_PROMPT_HEADER,
  generateAiFixPrompt,
  stripAnsiCodes,
  type AiPromptInput,
  type AiPromptIssue,
} from './ai-prompt-gen.js';

export interface VibesaneReportInput extends AiPromptInput {
  message: string;
  reason?: string;
  skippedRoutes?: readonly string[];
  aiPrompt?: string | null;
}

export interface TerminalReportOptions {
  color?: boolean;
  isTTY?: boolean;
  env?: NodeJS.ProcessEnv;
}

export function shouldEnableColor(
  customOpt?: boolean,
  isTTY: boolean = Boolean(process.stdout?.isTTY),
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  if (env?.NO_COLOR !== undefined && env.NO_COLOR !== '') {
    return false;
  }
  if (typeof customOpt === 'boolean') {
    return customOpt;
  }
  return Boolean(isTTY);
}

function formatSummaryCodeFrame(rawFrame: string, maxLines = 10): string[] {
  const clean = stripAnsiCodes(rawFrame).replace(/\r\n/g, '\n').trimEnd();
  if (!clean) {
    return [];
  }
  return clean
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line, idx, arr) => !(line === '' && (idx === 0 || idx === arr.length - 1)))
    .slice(0, maxLines)
    .map((line) => `  ${line}`);
}

function injectMissingCodeFrames(
  summaryText: string,
  issues: readonly AiPromptIssue[],
): string {
  const issuesWithFrames = issues.filter(
    (i) => i.severity === 'error' && typeof i.codeFrame === 'string' && i.codeFrame.trim().length > 0,
  );
  if (issuesWithFrames.length === 0) {
    return summaryText;
  }

  const lines = summaryText.split('\n');
  const out: string[] = [];
  const usedIssueIndices = new Set<number>();

  for (const line of lines) {
    out.push(line);
    if (!line.startsWith('error [')) {
      continue;
    }

    const matchIdx = issuesWithFrames.findIndex((issue, idx) => {
      if (usedIssueIndices.has(idx)) {
        return false;
      }
      return line.includes(`[${issue.kind}]`) && line.includes(issue.route);
    });

    if (matchIdx !== -1) {
      usedIssueIndices.add(matchIdx);
      const frameLines = formatSummaryCodeFrame(issuesWithFrames[matchIdx]!.codeFrame!);
      const firstFrameLine = frameLines[0]?.trim();
      if (firstFrameLine && !summaryText.includes(firstFrameLine)) {
        out.push(...frameLines);
      }
    }
  }

  return out.join('\n');
}

function styleSummaryLines(summaryText: string, ok: boolean): string {
  return summaryText
    .split('\n')
    .map((line) => {
      if (ok && line.startsWith('vibesane: connected to ')) {
        return styleText('green', line);
      }
      if (!ok && (line.startsWith('vibesane: sanity check failed') || line.startsWith('error '))) {
        return styleText('red', line);
      }
      if (line.startsWith('warning ')) {
        return styleText('yellow', line);
      }
      return line;
    })
    .join('\n');
}

export function formatTerminalReport(
  result: VibesaneReportInput,
  options: TerminalReportOptions = {},
): string {
  const useColor = shouldEnableColor(options.color, options.isTTY, options.env);
  const hasErrors =
    Array.isArray(result.issues) &&
    result.issues.some((issue) => issue.severity === 'error');

  if (result.port === null || (!result.ok && !hasErrors)) {
    return useColor ? styleText('red', result.message) : result.message;
  }

  if (result.ok) {
    if (!useColor) {
      return result.message;
    }
    return styleSummaryLines(result.message, true);
  }

  let summarySection = result.message;
  let existingPromptSection: string | null = null;

  const headerIndex = result.message.indexOf(AI_PROMPT_HEADER);
  if (headerIndex !== -1) {
    summarySection = result.message.slice(0, headerIndex).trimEnd();
    existingPromptSection = result.message.slice(headerIndex);
  }

  summarySection = injectMissingCodeFrames(summarySection, result.issues);
  const renderedSummary = useColor
    ? styleSummaryLines(summarySection, false)
    : summarySection;

  const promptBlock =
    existingPromptSection ??
    (result.aiPrompt !== undefined ? result.aiPrompt : generateAiFixPrompt(result));

  if (!promptBlock) {
    return renderedSummary;
  }

  return `${renderedSummary}\n\n${stripAnsiCodes(promptBlock)}`;
}

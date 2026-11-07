import { isPublicEnvVarName } from './exceptions.js';

export const SERVER_ENV_ACCESS_RE =
  /\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\\?["']([A-Za-z_][A-Za-z0-9_]*)\\?["']\])/g;

export function isServerEnvVarName(varName: string): boolean {
  if (!varName || isPublicEnvVarName(varName)) {
    return false;
  }
  return (
    varName.includes('SERVICE_ROLE') ||
    varName.endsWith('_SECRET') ||
    varName.endsWith('_SECRET_KEY') ||
    varName.endsWith('_PRIVATE_KEY') ||
    varName === 'DATABASE_URL'
  );
}

export const SERVER_ENV_RULE_EXAMPLES = {
  shouldDetect: [
    'process.env.SUPABASE_SERVICE_ROLE_KEY',
    '__["default"].env.SUPABASE_SERVICE_ROLE_KEY',
    'r(357).env.SUPABASE_SERVICE_ROLE_KEY',
    'import.meta.env.DATABASE_URL',
    'process.env.JWT_SECRET',
    'process.env.API_PRIVATE_KEY',
    'process.env.STRIPE_SECRET_KEY',
    'process.env["DATABASE_URL"]',
    'process.env[\\"DATABASE_URL\\"]',
    'r.env[\'AUTH_SECRET_KEY\']',
  ],
  shouldIgnore: [
    'process.env.NEXT_PUBLIC_SUPABASE_URL',
    'import.meta.env.VITE_APP_KEY',
    'process.env.NEXT_PUBLIC_SERVICE_ROLE_KEY',
    'import.meta.env.VITE_DATABASE_URL',
    'process.env.NODE_ENV',
    'process.env.PORT',
    'process.env.PUBLIC_URL',
  ],
} as const;

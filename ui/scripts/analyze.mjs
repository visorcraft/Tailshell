import { spawnSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';

const bin = process.platform === 'win32' ? 'node_modules/.bin/vite.cmd' : 'node_modules/.bin/vite';
const vite = path.resolve(process.cwd(), bin);

const result = spawnSync(vite, ['build'], {
  stdio: 'inherit',
  env: { ...process.env, ANALYZE: '1' }
});

process.exit(result.status ?? 1);


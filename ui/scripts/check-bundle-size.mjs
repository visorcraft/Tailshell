import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(value >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}

function gzipBytes(buffer) {
  return zlib.gzipSync(buffer, { level: 9 }).length;
}

function readJson(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw);
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const distDir = path.resolve(root, 'dist');
const assetsDir = path.resolve(distDir, 'assets');
const budgetsPath = path.resolve(root, 'bundle-budgets.json');

if (!fs.existsSync(assetsDir)) {
  console.error(`Missing build output at ${assetsDir}. Run: npm run build`);
  process.exit(2);
}

if (!fs.existsSync(budgetsPath)) {
  console.error(`Missing ${budgetsPath}. Create a budget file (see TASKS.md) and rerun.`);
  process.exit(2);
}

const budgets = readJson(budgetsPath);
const gzipBudget = budgets?.gzip ?? {};

const files = fs.readdirSync(assetsDir, { withFileTypes: true }).filter((d) => d.isFile());

const jsFiles = [];
const cssFiles = [];

for (const entry of files) {
  const ext = path.extname(entry.name).toLowerCase();
  if (ext === '.js') jsFiles.push(entry.name);
  if (ext === '.css') cssFiles.push(entry.name);
}

const stats = {
  js: { rawTotal: 0, gzipTotal: 0, gzipMaxChunk: 0, maxChunkName: null },
  css: { rawTotal: 0, gzipTotal: 0 }
};

for (const name of jsFiles) {
  const buffer = fs.readFileSync(path.join(assetsDir, name));
  const raw = buffer.length;
  const gz = gzipBytes(buffer);
  stats.js.rawTotal += raw;
  stats.js.gzipTotal += gz;
  if (gz > stats.js.gzipMaxChunk) {
    stats.js.gzipMaxChunk = gz;
    stats.js.maxChunkName = name;
  }
}

for (const name of cssFiles) {
  const buffer = fs.readFileSync(path.join(assetsDir, name));
  stats.css.rawTotal += buffer.length;
  stats.css.gzipTotal += gzipBytes(buffer);
}

console.log('Bundle size (dist/assets)');
console.log(`- JS total:  ${formatBytes(stats.js.rawTotal)} raw / ${formatBytes(stats.js.gzipTotal)} gzip`);
console.log(`- JS largest: ${formatBytes(stats.js.gzipMaxChunk)} gzip (${stats.js.maxChunkName ?? 'n/a'})`);
console.log(`- CSS total: ${formatBytes(stats.css.rawTotal)} raw / ${formatBytes(stats.css.gzipTotal)} gzip`);

const failures = [];

const checkMax = (name, actual, max) => {
  if (!Number.isFinite(max) || max <= 0) return;
  if (actual > max) failures.push(`${name} exceeded: ${formatBytes(actual)} > ${formatBytes(max)}`);
};

checkMax('gzip.jsTotalMaxBytes', stats.js.gzipTotal, gzipBudget.jsTotalMaxBytes);
checkMax('gzip.jsMaxChunkMaxBytes', stats.js.gzipMaxChunk, gzipBudget.jsMaxChunkMaxBytes);
checkMax('gzip.cssTotalMaxBytes', stats.css.gzipTotal, gzipBudget.cssTotalMaxBytes);

if (failures.length > 0) {
  console.error('\nBundle size budgets failed:');
  for (const line of failures) console.error(`- ${line}`);
  process.exit(1);
}


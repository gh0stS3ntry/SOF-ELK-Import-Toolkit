// Optional syntax check of every hunting query with Elastic's own ES|QL parser (@elastic/esql).
// It catches what check_queries.py cannot: bad string escapes, reserved words used as names,
// unbalanced quotes and parentheses. It needs Node.js 18+ and network access once:
//
//   npm install --prefix /tmp/esql @elastic/esql
//   node hunting/tools/parse_queries.mjs /tmp/esql            # every query.esql in the pack
//   node hunting/tools/parse_queries.mjs /tmp/esql path/to/query.esql ...
import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
import { fileURLToPath, pathToFileURL } from 'url';

const [prefix, ...files] = process.argv.slice(2);
if (!prefix) {
  console.error('usage: node parse_queries.mjs <npm prefix holding @elastic/esql> [query.esql ...]');
  process.exit(2);
}
const require = createRequire(path.join(path.resolve(prefix), 'node_modules', 'noop.js'));
const { Parser } = await import(pathToFileURL(require.resolve('@elastic/esql')).href);

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(dir, e.name)) : e.name === 'query.esql' ? [path.join(dir, e.name)] : []);
}

const queries = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'queries');
const targets = files.length ? files : walk(queries).sort();
let bad = 0;
for (const f of targets) {
  const { errors } = Parser.parse(fs.readFileSync(f, 'utf8'));
  if (errors.length) {
    bad++;
    console.log(path.relative(process.cwd(), f));
    for (const e of errors) console.log(`    ${e.startLineNumber}:${e.startColumn} ${e.message}`);
  }
}
console.log(`${targets.length} queries parsed, ${bad} with syntax errors`);
process.exit(bad ? 1 : 0);

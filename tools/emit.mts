// Emits the plain JavaScript that consumers load from node_modules: node refuses to strip
// types from files installed there. The TypeScript under runtime/ stays the source of truth;
// `node tools/emit.mts` rewrites the generated .mjs files, `--check` fails when they are stale.
import {readdir,readFile,writeFile} from 'node:fs/promises';
import {stripTypeScriptTypes} from 'node:module';

const directory=new URL('../runtime/',import.meta.url);
const check=process.argv.includes('--check');
let stale=0;
for(const name of (await readdir(directory)).filter(entry=>entry.endsWith('.mts')).sort()) {
  const source=await readFile(new URL(name,directory),'utf8');
  const code=stripTypeScriptTypes(source,{mode:'strip'})
    .replace(/(from\s+|import\s*\()(['"])(\.\/[^'"]+)\.mts\2/g,'$1$2$3.mjs$2');
  const output=`// Generated from ${name} by tools/emit.mts. Do not edit.\n${code}`;
  const target=new URL(name.replace(/\.mts$/,'.mjs'),directory);
  const current=await readFile(target,'utf8').catch(()=>undefined);
  if(current===output)continue;
  if(check){console.error(`stale: ${target.pathname}`);stale++;}
  else await writeFile(target,output);
}
if(stale)process.exit(1);

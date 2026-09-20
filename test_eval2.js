const fs = require('fs');
const vm = require('vm');

const js = fs.readFileSync('chunk_174_chunks_BYlv1dKC.js', 'utf8');

const euStart = js.indexOf('function eu(){');
const euEnd = js.indexOf('function fl(){', euStart);
const rotStart = js.lastIndexOf('(function(e,t)', euStart);
const rotEnd = js.indexOf(');', js.indexOf(')(eu,', rotStart)) + 2;

const rotCode = js.slice(rotStart, rotEnd);
const euCode = js.slice(euStart, euEnd);
const FrCode = 'function Fr(e,t){return e=e+422,eu()[e]}';

const ctx = {
  console,
  Uint8Array,
  Array,
  String,
  Number,
  Math,
  JSON,
  Date,
  Error,
  Symbol,
  parseInt,
  crypto: require('crypto').webcrypto,
  TextEncoder
};
ctx.globalThis = ctx;
vm.createContext(ctx);

async function run() {
  vm.runInContext(FrCode + '\n' + euCode + '\n' + rotCode, ctx);
  const configCode = js.slice(euEnd - 500, euEnd);
  const fdIdx = configCode.indexOf('const fd=');
  vm.runInContext(configCode.slice(fdIdx), ctx);

  const i_Start = js.indexOf('function i_(');
  const xyStart = js.indexOf('async function xy('); // The function after cT
  const cryptoChunk = js.slice(i_Start, xyStart);
  
  vm.runInContext(cryptoChunk, ctx);

  const tokenK9 = await ctx.cT({ buildId: '174', epoch: 2959, keyGroup: 'mkissa', refererHost: 'mkissa.to', contentLane: 'k9' });
  const tokenK7 = await ctx.cT({ buildId: '174', epoch: 2959, keyGroup: 'mkissa', refererHost: 'mkissa.to', contentLane: 'k7' });

  console.log('k9 boot token:', tokenK9);
  console.log('k7 boot token:', tokenK7);
}

run().catch(console.error);

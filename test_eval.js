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

// Extract cT and helper functions
const cTStart = js.indexOf('async function cT');
const cTEnd = js.indexOf('function gy(', cTStart);
const cTCode = js.slice(cTStart, cTEnd);

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
};
ctx.globalThis = ctx;
vm.createContext(ctx);

let logText = '';
async function run() {
  try {
    vm.runInContext(FrCode + '\n' + euCode + '\n' + rotCode, ctx);
    const configCode = js.slice(euEnd - 500, euEnd);
    const fdIdx = configCode.indexOf('const fd=');
    vm.runInContext(configCode.slice(fdIdx), ctx);

    // Run crypto code
    const cryptoChunk = js.slice(js.indexOf('function i_('), js.indexOf('async function xy(') + 1500);
    vm.runInContext(cryptoChunk, ctx);

    const tokenK9 = await ctx.cT({ buildId: '174', epoch: 2959, keyGroup: 'mkissa', refererHost: 'mkissa.to', contentLane: 'k9' });
    const tokenK7 = await ctx.cT({ buildId: '174', epoch: 2959, keyGroup: 'mkissa', refererHost: 'mkissa.to', contentLane: 'k7' });

    logText += 'k9 boot token: ' + tokenK9 + '\n';
    logText += 'k7 boot token: ' + tokenK7 + '\n';
  } catch (e) {
    logText += 'ERR: ' + e.stack + '\n';
  }
  fs.writeFileSync('/Users/tejas/Desktop/Tejas/My Projects/animanga-BE/anime-relay/res.txt', logText);
}

run();

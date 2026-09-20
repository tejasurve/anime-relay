const { bootToken, keyGroupForHost } = require('./src/aacrypto.js');

const maskHex = "04cb708eea31ffee4d31b5b4b53b9c824c2bc78be740d36446d01be13c43e399";
// Wait, I need params.
// Let's get params from state.material
const { scan } = require('./src/bundle.js');
scan().then(({ material }) => {
  const token = bootToken({
    maskHex: material.maskHex,
    params: material.params,
    buildId: material.buildId,
    epoch: 2959,
    lane: "k9",
    host: "isekai2nd.com",
  });
  console.log("Generated token for k9 isekai2nd.com:", token);
});

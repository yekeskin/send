const fetch = require('node-fetch');
const config = require('./config');
const jwt = require('jsonwebtoken');
const njwk = require('node-jwk');

const KEY_SCOPE = config.fxa_key_scope;
let fxaConfig = null;
let lastConfigRefresh = 0;

async function getFxaConfig() {
  if (fxaConfig && Date.now() - lastConfigRefresh < 1000 * 60 * 5) {
    return fxaConfig;
  }
  try {
    const res = await fetch(
      `${config.fxa_url}/.well-known/openid-configuration`,
      { timeout: 3000 }
    );
    fxaConfig = await res.json();
    fxaConfig.key_scope = KEY_SCOPE;
    fxaConfig.redirect_uri = config.base_url;
    lastConfigRefresh = Date.now();
  } catch (e) {
    // continue with previous fxaConfig
  }
  return fxaConfig;
}

module.exports = {
  getFxaConfig,
  verify: async function(token) {
    if (!token) {
      return null;
    }

    const c = await getFxaConfig();
    try {
      const infoRequest = await fetch(c.jwks_uri, {
        method: 'GET'
      });
      const info = await infoRequest.json();
      const keySet = njwk.JWKSet.fromJSON(JSON.stringify(info));
      const decoded = jwt.decode(token, { complete: true });
      const jwk = keySet.findKeyById(decoded.header.kid);
      if (jwk && jwt.verify(token, jwk.key.toPublicKeyPEM())) {
        return decoded.payload;
      }
    } catch (e) {
      // gulp
    }
    return null;
  }
};

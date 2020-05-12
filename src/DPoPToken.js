const AccessToken = require('./AccessToken')
const JWT = require('jsonwebtoken')
const { jwkThumbprintByEncoding } = require('jwk-thumbprint')
const {UnauthorizedError} = require('./errors/index')
const jwkToPem = require('jwk-to-pem')
const URL = require('url').URL;

class DPoPToken extends AccessToken {
  /**
   * @param jwt {JWT}
   *
   * @param jwt.payload {Object}
   */
  constructor (jwt, dpopHeader, serverUri, req) {
    super(jwt)
    this.isPoPToken = true
    this.dpopHeader = dpopHeader
    this.serverUri = serverUri
    this.req = req
  }

  async validatePoPToken () {
    // decode header token
    const decodedHeaderToken = await JWT.decode(this.dpopHeader, { json: true, complete: true })
    // verify the dpop token is signed by the valid JWK
    try {
      await JWT.verify(this.dpopHeader, jwkToPem(decodedHeaderToken.header.jwk))
    } catch (err) {
      throw new UnauthorizedError({
        error: 'invalid_token',
        error_description: err.message
      })
    }
    // verify the the dpop header JWK is equal to the access token cnf
    try {
      const dpopHeaderThumbprint = jwkThumbprintByEncoding(decodedHeaderToken.header.jwk, "SHA-256", 'base64url')
      if (this.jwt.payload.cnf.jkt !== dpopHeaderThumbprint) {
        throw new Error('Access token cnf does not match the DPoP header JWK')
      }
    } catch (err) {
      throw new UnauthorizedError({
        error: 'invalid_token',
        error_description: err.message
      })
    }
    // verify htu and htm
    let requiredHtu = new URL(`${this.serverUri}${this.req.path}`)
    if (this.isSubdomain(requiredHtu.host, this.req.get('host'))) {
      requiredHtu.host = this.req.get('host')
    }
    requiredHtu = requiredHtu.toString()
    if (decodedHeaderToken.payload.htu !== requiredHtu) {
      throw new UnauthorizedError({
        error: 'invalid_token',
        error_description: `htu ${decodedHeaderToken.payload.htu} does not match ${requiredHtu}`
      })
    }
    if (decodedHeaderToken.payload.htm !== this.req.method) {
      throw new Error({
        error: 'invalid_token',
        error_description: `htm ${decodedHeaderToken.payload.htm} does not match ${this.req.method}`
      })
    }
  }

  isSubdomain (domain, subdomain) {
    const domainArr = domain.split('.')
    const subdomainArr = subdomain.split('.')
    for (let i = 1; i <= domainArr.length; i++) {
      if (subdomainArr[subdomainArr.length - i] !== domainArr[domainArr.length - i]) {
        return false
      }
    }
    return true
  }
}

module.exports = DPoPToken

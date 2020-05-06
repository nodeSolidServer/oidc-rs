const AccessToken = require('./AccessToken')
const JWT = require('jsonwebtoken')
const jwkToPem = require('jwk-to-pem')

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

    try {
      // decode header token
      const decodedHeaderToken = await JWT.decode(this.dpopHeader, { json: true, complete: true })
      // verify the auth token contains the correct public key
      await JWT.verify(this.dpopHeader, jwkToPem(this.jwt.payload.cnf))
      // verify htu and htm
      let requiredHtu = new URL(`${this.serverUri}${this.req.path}`)
      if (this.isSubdomain(requiredHtu.host, this.req.get('host'))) {
        requiredHtu.host = this.req.get('host')
      }
      requiredHtu = requiredHtu.toString()
      if (decodedHeaderToken.payload.htu !== requiredHtu) {
        throw new Error(`htu ${decodedHeaderToken.payload.htu} does not match ${requiredHtu}`)
      }
      if (decodedHeaderToken.payload.htm !== this.req.method) {
        throw new Error(`htm ${decodedHeaderToken.payload.htm} does not match ${this.req.method}`)
      }
    } catch (err) {
      return false;
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

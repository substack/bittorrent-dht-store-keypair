var ed = require('supercop.wasm')
var JSSHA = require('jssha/src/sha1')

module.exports = KP

function KP (opts) {
  if (!(this instanceof KP)) return new KP(opts)
  if (!opts) opts = {}
  this.secretKey = opts.secretKey
  this.publicKey = opts.publicKey
  if (typeof this.secretKey === 'string') {
    this.secretKey = Buffer.from(this.secretKey, 'hex')
  }
  if (typeof this.publicKey === 'string') {
    this.publicKey = Buffer.from(this.publicKey, 'hex')
  }
  if (!this.secretKey && !this.publicKey) {
    var kp = ed.createKeyPair(this.seed || ed.createSeed())
    this.secretKey = kp.secretKey
    this.publicKey = kp.publicKey
  }
  var shaObj = new JSSHA('SHA-1', 'ARRAYBUFFER')
  shaObj.update(this.publicKey)
  this.id = shaObj.getHash('HEX')
  this.seq = 'seq' in opts ? opts.seq : 0
}

KP.prototype.sign = function (value) {
  if (typeof value === 'string') value = Buffer.from(value)
  return Buffer.from(ed.sign(value, this.publicKey, this.secretKey))
}

KP.prototype.store = function (value, opts) {
  var self = this
  if (!opts) opts = {}
  if (typeof value === 'string') value = Buffer.from(value)
  var seq = 'seq' in opts ? opts.seq : this.seq
  if (opts.seq === undefined) this.seq ++
  var salt = typeof opts.salt === 'string' ? Buffer.from(opts.salt) : opts.salt
  return {
    k: Buffer.from(this.publicKey),
    seq: seq,
    salt: salt,
    v: value,
    sign: self.sign.bind(self)
  }
}

KP.verify = ed.verify

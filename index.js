var ed = require('ed25519-supercop')
var sha = require('sha.js')
var defined = require('defined')

module.exports = KP

function KP (opts) {
  if (!(this instanceof KP)) return new KP(opts)
  if (!opts) opts = {}
  this.secretKey = opts.secretKey
  this.publicKey = opts.publicKey
  if (typeof this.secretKey === 'string') {
    this.secretKey = Buffer(this.secretKey, 'hex')
  }
  if (typeof this.publicKey === 'string') {
    this.publicKey = Buffer(this.publicKey, 'hex')
  }
  if (!this.secretKey && !this.publicKey) {
    var kp = ed.createKeyPair(this.seed || ed.createSeed())
    this.secretKey = kp.secretKey
    this.publicKey = kp.publicKey
  }
  this.id = sha('sha1').update(this.publicKey).digest('hex')
  this.seq = defined(opts.seq, 0)
}

KP.prototype.sign = function (value) {
  return ed.sign(value, this.publicKey, this.secretKey)
}

KP.prototype.store = function (value, opts) {
  var self = this
  if (!opts) opts = {}
  if (typeof value === 'string') value = Buffer(value)
  var seq = defined(opts.seq, this.seq)
  if (opts.seq === undefined) this.seq ++
  var salt = typeof opts.salt === 'string' ? Buffer(opts.salt) : opts.salt
  return {
    k: this.publicKey,
    seq: seq,
    salt: salt,
    v: value,
    sign: function (buf) {
      return ed.sign(buf, self.publicKey, self.secretKey)
    }
  }
}

KP.verify = ed.verify

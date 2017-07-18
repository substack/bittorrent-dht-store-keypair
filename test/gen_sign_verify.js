var test = require('tape')
var KP = require('../')
var ed = require('supercop.wasm')

test('generate, sign, verify', function (t) {
  t.plan(4)
  var kp = new KP()
  var msg = Buffer.from('whatever')
  var sig = kp.sign(msg)
  var xsig = xmod(sig)
  var xmsg = xmod(msg)
  var xpk = xmod(kp.publicKey)

  t.ok(ed.verify(sig, msg, kp.publicKey))
  t.notOk(ed.verify(xsig, msg, kp.publicKey))
  t.notOk(ed.verify(sig, xmsg, kp.publicKey))
  t.notOk(ed.verify(sig, msg, xpk))
})

function xmod (buf) {
  var cp = Buffer(buf)
  cp[0] = ~cp[0]
  return cp
}

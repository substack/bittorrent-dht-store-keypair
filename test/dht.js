var test = require('tape')
var DHT = require('bittorrent-dht')
var KP = require('../')

test('dht hex keys', function (t) {
  t.plan(3)
  var dht0 = new DHT({ bootstrap: false, verify: KP.verify })
  var dht1 = new DHT({ bootstrap: false, verify: KP.verify })
  var kp0 = new KP({
    publicKey: '4e9c1662b42a1530c1a3e2e6af93a65e845c06ae7d42a65653d31875817ea3d7',
    secretKey: '408e939cab7a2c42da6ac588c04d5273fe4bbfe4ed49635c46b2e8aeb02713710'
      + '4872f12834d19fa5d2d7b187f11a164b8ceedf7df07a82ab2d7f6dc7851f06f',
  })
  t.once('end', function () {
    dht0.destroy()
    dht1.destroy()
  })

  dht0.listen(function () {
    dht1.addNode({host: '127.0.0.1', port: dht0.address().port})
    dht1.once('node', function () {
      dht0.put(kp0.store('wow'), function (error, hash) {
        if (error) {
          t.fail(error.message)
        }
        t.equal(
          hash.toString('hex'),
          'f3f10aff933ed0b79bdbf3de21fe426f482f14fc'
        )
        dht1.get(hash, function (err, node) {
          t.ifError(err)
          t.equal(node.v.toString(), 'wow')
        })
      })
    })
  })
})

test('dht generated key', function (t) {
  t.plan(2)
  var dht0 = new DHT({ bootstrap: false, verify: KP.verify })
  var dht1 = new DHT({ bootstrap: false, verify: KP.verify })
  var kp0 = new KP
  t.once('end', function () {
    dht0.destroy()
    dht1.destroy()
  })

  dht0.listen(function () {
    dht1.addNode({host: '127.0.0.1', port: dht0.address().port})
    dht1.once('node', function () {
      dht0.put(kp0.store('wow'), function (error, hash) {
        if (error) {
          t.fail(error.message)
        }
        dht1.get(hash, function (err, node) {
          t.ifError(err)
          t.equal(node.v.toString(), 'wow')
        })
      })
    })
  })
})

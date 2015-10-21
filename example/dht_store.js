#!/usr/bin/env node

/*
Store or retrieve arbitrary immutable or mutable value via BitTorrent DHT.

immutable:
$ ./dht_store.js put "hello DHT"
put result: 439b79a37b823d034c97fc896a7b0b9429449ea6
$ ./dht_store.js get 439b79a37b823d034c97fc896a7b0b9429449ea6
get result: hello DHT

mutable:
$ ./dht_store.js genkey > keypair.json
$ ./dht_store.js put keypair.json "hello DHT"
put result: 08ceb171c1290f2af325247b728db452bbce2107
$ ./dht_store.js get 08ceb171c1290f2af325247b728db452bbce2107
get result: hello DHT
*/

var DHT = require('bittorrent-dht')
var KP = require('bittorrent-dht-store-keypair')
var path = require('path')
var args = require('minimist')(process.argv.slice(2))

var first = args._[0]
var second = args._[1]
var third = args._[2]
var kp = KP()

function usage()
{
    console.log('Store and retrieve arbitrary data from the BitTorrent DHT.')
    console.log('Usage: ./dht_store.js [genkey/put/get] <keypair.json> value (max size <= 1000 bytes)')
    process.exit(-1)
}

function show_result(res)
{
    console.log(first + ' result: ' + res)
    process.exit(0)
}

if (!first || args._[3]) usage()

if (first === 'genkey') {
    console.log(JSON.stringify({
        publicKey: kp.publicKey.toString('hex'),
        secretKey: kp.secretKey.toString('hex')
    }))
    process.exit(0)
}

var dht = new DHT({verify: KP.verify})
var value = undefined

if (first === 'put' && third) {
    kp = KP(require(path.resolve(second)))
    value = kp.store(third)
}

else if(first === 'put' && !third)
    value = {v : second}

if(first != 'get' && !value)
    usage()

dht.on('ready', function(){
    if (first === 'get') {
        dht.get(second, function (err, res) {
            if (err) console.log(err)
            if (res) show_result(res.v.toString())
        })
    }
    if (first === 'put') {
        dht.put(value, function (err, res) {
            if (err) console.log(err)
            if (res) show_result(res.toString('hex'))
        })
    }
})

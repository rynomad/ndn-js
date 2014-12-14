/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Wentao Shang
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

var ASN1HEX = require('../contrib/securityLib/asn1hex-1.1.js').ASN1HEX
var KJUR = require('../contrib/securityLib/crypto-1.0.js').KJUR
var RSAKey = require('../contrib/securityLib/rsasign-1.2.js').RSAKey
var b64tohex = require('../contrib/securityLib/base64.js').b64tohex

// Library namespace
var ndn = ndn || {};

var key ;
ndn.Key = require("./key.js").Key

var exports = ndn;


// Factory method to create hasher objects
exports.createHash = function(alg)
{

  var obj = {};

  if (alg != 'sha256')
    throw new Error('createHash: unsupported algorithm.');

  if(crypto.subtle && location.protocol === "https:"){
    var toDigest = new Buffer(0);
    obj.update = function(buf){
      toDigest = Buffer.concat([toDigest, buf]);
    }

    obj.digest = function(cb){
      var done = false;
      return crypto.subtle.digest({name:"SHA-256"}, toDigest.buffer).then(function(result){
        cb(new Buffer(new Uint8Array(result)));
      })
    }
  } else {
    obj.md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});

    obj.update = function(buf) {
      this.md.updateHex(buf.toString('hex'));
    };

    obj.digest = function() {
      return new Buffer(this.md.digest(), 'hex');
    };
  }

  return obj;
};

var privateKey = false;
// Factory method to create RSA signer objects
exports.createSign = function(alg)
{
  if (alg != 'RSA-SHA256')
    throw new Error('createSign: unsupported algorithm.');

  var obj = {};

  if(crypto.subtle && location.protocol === "https:"){
    var toSign;

    obj.update = function(buf){
      toSign = buf;
    }

    obj.sign = function(keypem, cb){
      if (!privateKey){
        crypto.subtle.generateKey(
          { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash:{name:"SHA-256"}, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) },
            true,
            ["sign"]).then(function(result){
              privateKey = result.privateKey;
              return crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, result.privateKey, toSign);
        }).then(function(signedArrayBuffer){
          cb(new Buffer(new Uint8Array(signedArrayBuffer)));
        });
      } else {
        crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, privateKey, toSign).then(function(signature){

          cb(new Buffer(new Uint8Array(signature)));
        })
      }
    }
  } else {

    obj.arr = [];

    obj.update = function(buf) {
      this.arr.push(buf);
    };

    obj.sign = function(keypem) {
      var rsa = new RSAKey();
      rsa.readPrivateKeyFromPEMString(keypem);
      var signer = new KJUR.crypto.Signature({alg: "SHA256withRSA", prov: "cryptojs/jsrsa"});
      signer.initSign(rsa);
      for (var i = 0; i < this.arr.length; ++i)
        signer.updateHex(this.arr[i].toString('hex'));

      return new Buffer(signer.sign(), 'hex');
    };
  }

  return obj;
};

// Factory method to create RSA verifier objects
exports.createVerify = function(alg)
{
  if (alg != 'RSA-SHA256')
    throw new Error('createSign: unsupported algorithm.');

  var obj = {};

  obj.arr = [];

  obj.update = function(buf) {
    this.arr.push(buf);
  };

  var getSubjectPublicKeyPosFromHex = function(hPub) {
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hPub, 0);
    if (a.length != 2)
      return -1;
    var pBitString = a[1];
    if (hPub.substring(pBitString, pBitString + 2) != '03')
      return -1;
    var pBitStringV = ASN1HEX.getStartPosOfV_AtObj(hPub, pBitString);
    if (hPub.substring(pBitStringV, pBitStringV + 2) != '00')
      return -1;
    return pBitStringV + 2;
  };

  var readPublicDER = function(pub_der) {
    var hex = pub_der.toString('hex');
    var p = getSubjectPublicKeyPosFromHex(hex);
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(hex, p);
    if (a.length != 2)
      return null;
    var hN = ASN1HEX.getHexOfV_AtObj(hex, a[0]);
    var hE = ASN1HEX.getHexOfV_AtObj(hex, a[1]);
    var rsaKey = new RSAKey();
    rsaKey.setPublic(hN, hE);
    return rsaKey;
  };

  obj.verify = function(keypem, sig) {
    var key = new ndn.Key();
    key.fromPemString(keypem);

    var rsa = readPublicDER(key.publicToDER());
    var signer = new KJUR.crypto.Signature({alg: "SHA256withRSA", prov: "cryptojs/jsrsa"});
    signer.initVerifyByPublicKey(rsa);
    for (var i = 0; i < this.arr.length; i++)
      signer.updateHex(this.arr[i].toString('hex'));
    var hSig = sig.toString('hex');
    return signer.verify(hSig);
  };

  return obj;
};

exports.randomBytes = function(size)
{
  // TODO: Use a cryptographic random number generator.
  var result = new Buffer(size);
  for (var i = 0; i < size; ++i)
    result[i] = Math.floor(Math.random() * 256);
  return result;
};

// contrib/feross/buffer.js needs base64.toByteArray. Define it here so that
// we don't have to include the entire base64 module.
exports.toByteArray = function(str) {
  var hex = b64tohex(str);
  var result = [];
  hex.replace(/(..)/g, function(ss) {
    result.push(parseInt(ss, 16));
  });
  return result;
};

module.exports = exports
// After this we include contrib/feross/buffer.js to define the Buffer class.

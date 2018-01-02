/**
 * This module checks for the availability of various crypto.subtle api's at runtime,
 * exporting a function that returns the known availability of necessary NDN crypto apis
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Ryan Bennett <nomad.ry@gmail.com>
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

function DetectSubtleCrypto(){
  var use = false;
  var baselineSupport = (
                            (typeof crypto !== 'undefined' && crypto && crypto.subtle)
                            && (
                                (location.protocol === "https:" || "chrome-extension:" || "chrome:")
                                || (location.hostname === "localhost" || location.hostname === "127.0.0.1")
                               )
                        ) ? true : false ;
  if (baselineSupport) {
    var algo = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash:{name:"SHA-256"}, publicExponent: new Uint8Array([0x01, 0x00, 0x01])};
    var keypair;
    //try to perform every RSA crypto operation we need, if everything works, set use = true
    crypto.subtle.generateKey(
      algo,
      true, //exportable;
      ["sign", "verify"]).then(function(key){
        keypair = key;
        return crypto.subtle.sign(algo, key.privateKey, new Uint8Array([1,2,3,4,5]));
      }).then(function(signature){
        return crypto.subtle.verify(algo, keypair.publicKey, signature, new Uint8Array([1,2,3,4,5]));
      }).then(function(verified){
        return crypto.subtle.exportKey("pkcs8",keypair.privateKey);
      }).then(function(pkcs8){
        return crypto.subtle.importKey("pkcs8", pkcs8, algo, true, ["sign"]);
      }).then(function(importedKey){
        return crypto.subtle.exportKey("spki", keypair.publicKey);
      }).then(function(spki){
        return crypto.subtle.importKey("spki", spki, algo, true, ["verify"]);
      }).then(function(importedKey){
        var testDigest = new Uint8Array([1,2,3,4,5]);
        return crypto.subtle.digest({name:"SHA-256"}, testDigest.buffer);
      }).then(function(result){
        use = true;
      }, function(err){
        console.log("DetectSubtleCrypto encountered error, not using crypto.subtle: ", err)
      });
  }
  return function useSubtleCrypto(){
    return use;
  }
}

var UseSubtleCrypto = DetectSubtleCrypto();

exports.UseSubtleCrypto = UseSubtleCrypto;

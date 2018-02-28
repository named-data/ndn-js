/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/verification-helpers.cpp
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

/** @ignore */
var Crypto = require('../crypto.js'); /** @ignore */
var SyncPromise = require('../util/sync-promise.js').SyncPromise; /** @ignore */
var Blob = require('../util/blob.js').Blob; /** @ignore */
var WireFormat = require('../encoding/wire-format.js').WireFormat; /** @ignore */
var KeyType = require('./security-types.js').KeyType; /** @ignore */
var DigestAlgorithm = require('./security-types.js').DigestAlgorithm; /** @ignore */
var UseSubtleCrypto = require("../use-subtle-crypto-node.js").UseSubtleCrypto; /** @ignore */
var CertificateV2 = require('./v2/certificate-v2.js').CertificateV2; /** @ignore */
var PublicKey = require('./certificate/public-key.js').PublicKey;

/**
 * The VerificationHelpers class has static methods to verify signatures and
 * digests.
 */
var VerificationHelpers = function VerificationHelpers() {};

exports.VerificationHelpers = VerificationHelpers;

/**
 * Verify the buffer against the signature using the public key.
 * @param {Buffer|Blob} buffer The input buffer to verify.
 * @param {Buffer|Blob} signature The signature bytes.
 * @param {PublicKey|Buffer|Blob} publicKey The object containing the public key,
 * or the public key DER which is used to make the PublicKey object.
 * @param {number} digestAlgorithm (optional) The digest algorithm as an int
 * from the DigestAlgorithm enum. If omitted, use DigestAlgorithm.SHA256.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if verification
 * succeeds, false if verification fails, or a promise rejected with Error for
 * an invalid public key type or digestAlgorithm.
 */
VerificationHelpers.verifySignaturePromise = function
  (buffer, signature, publicKey, digestAlgorithm, useSync)
{
  if (typeof digestAlgorithm === 'boolean') {
    // digestAlgorithm is omitted, so shift.
    useSync = digestAlgorithm;
    digestAlgorithm = undefined;
  }

  if (buffer instanceof Blob)
    buffer = buffer.buf();
  if (signature instanceof Blob)
    signature = signature.buf();
  if (!(publicKey instanceof PublicKey)) {
    // Turn publicKey into a PublicKey object.
    try {
      if (!(publicKey instanceof Blob))
        publicKey = new Blob(publicKey);
      publicKey = new PublicKey(publicKey);
    } catch (ex) {
      return SyncPromise.reject(new Error
        ("verifySignaturePromise: Error decoding public key DER: " + ex));
    }
  }
  if (digestAlgorithm == undefined)
    digestAlgorithm = DigestAlgorithm.SHA256;

  if (digestAlgorithm == DigestAlgorithm.SHA256) {
    if (publicKey.getKeyType() == KeyType.RSA) {
      if (UseSubtleCrypto() && !useSync) {
        var algo = {name:"RSASSA-PKCS1-v1_5", hash:{name:"SHA-256"}};

        return crypto.subtle.importKey
          ("spki", publicKey.getKeyDer().buf().buffer, algo, true, ["verify"])
        .then(function(key) {
          return crypto.subtle.verify(algo, key, signature, buffer)
        });
      }
      else {
        try {
          if (VerificationHelpers.verifyUsesString_ === null)
            VerificationHelpers.setVerifyUsesString_();

          // The crypto verifier requires a PEM-encoded public key.
          var keyBase64 = publicKey.getKeyDer().buf().toString('base64');
          var keyPem = "-----BEGIN PUBLIC KEY-----\n";
          for (var i = 0; i < keyBase64.length; i += 64)
            keyPem += (keyBase64.substr(i, 64) + "\n");
          keyPem += "-----END PUBLIC KEY-----";

          var verifier = Crypto.createVerify('RSA-SHA256');
          verifier.update(buffer);
          var signatureBytes = VerificationHelpers.verifyUsesString_ ?
            signature.toString('binary') : signature;
          return SyncPromise.resolve(verifier.verify(keyPem, signatureBytes));
        } catch (ex) {
          return SyncPromise.reject(new Error
            ("verifySignaturePromise: Error is RSA verify: " + ex));
        }
      }
    }
    else if (publicKey.getKeyType() == KeyType.EC) {
      try {
        if (VerificationHelpers.verifyUsesString_ === null)
          VerificationHelpers.setVerifyUsesString_();

        // The crypto verifier requires a PEM-encoded public key.
        var keyBase64 =  publicKey.getKeyDer().buf().toString("base64");
        var keyPem = "-----BEGIN PUBLIC KEY-----\n";
        for (var i = 0; i < keyBase64.length; i += 64)
          keyPem += (keyBase64.substr(i, 64) + "\n");
        keyPem += "-----END PUBLIC KEY-----";

        // Just create a "sha256". The Crypto library will infer ECDSA from the key.
        var verifier = Crypto.createVerify("sha256");
        verifier.update(buffer);
        var signatureBytes = VerificationHelpers.verifyUsesString_ ?
          signature.toString('binary') : signature;
        return SyncPromise.resolve(verifier.verify(keyPem, signatureBytes));
      } catch (ex) {
        return SyncPromise.reject(new Error
          ("verifySignaturePromise: Error is ECDSA verify: " + ex));
      }
    }
    else
      return SyncPromise.reject(new Error("verifySignaturePromise: Invalid key type"));
  }
  else
    return SyncPromise.reject(new Error
      ("verifySignaturePromise: Invalid digest algorithm"));
};

/**
 * Verify the buffer against the signature using the public key.
 * @param {Buffer|Blob} buffer The input buffer to verify.
 * @param {Buffer|Blob} signature The signature bytes.
 * @param {PublicKey|Buffer|Blob} publicKey The object containing the public key,
 * or the public key DER which is used to make the PublicKey object.
 * @param {number} digestAlgorithm (optional) The digest algorithm as an int
 * from the DigestAlgorithm enum. If omitted, use DigestAlgorithm.SHA256.
 * @param {function} onComplete (optional) This calls
 * onComplete(result) with true if verification succeeds, false if verification
 * fails. If omitted, the return value is described below. (Some crypto
 * libraries only use a callback, so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some crypto libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {boolean} If onComplete is omitted, return true if verification
 * succeeds, false if verification fails. Otherwise, if onComplete is supplied
 * then return undefined and use onComplete as described above.
 * @throws Error for an invalid public key type or digestAlgorithm. However, if
 * onComplete and onError are defined, then if there is an exception return
 * undefined and call onError(exception).
 */
VerificationHelpers.verifySignature = function
  (buffer, signature, publicKey, digestAlgorithm, onComplete, onError)
{
  if (typeof digestAlgorithm === 'function') {
    // digestAlgorithm is omitted, so shift.
    onError = onComplete;
    onComplete = digestAlgorithm;
    digestAlgorithm = undefined;
  }

  return SyncPromise.complete(onComplete, onError,
    this.verifySignaturePromise
      (buffer, signature, publicKey, digestAlgorithm, !onComplete));
};

/**
 * Verify the Data packet using the public key. This does not check the type of
 * public key or digest algorithm against the type of SignatureInfo in the Data
 * packet such as Sha256WithRsaSignature.
 * @param {Data} data The Data packet to verify.
 * @param {PublicKey|Buffer|Blob|CertificateV2} publicKeyOrCertificate The
 * object containing the public key, or the public key DER which is used to make
 * the PublicKey object, or the certificate containing the public key.
 * @param {number} digestAlgorithm (optional) The digest algorithm as an int
 * from the DigestAlgorithm enum. If omitted, use DigestAlgorithm.SHA256.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the Data packet. If omitted, use WireFormat getDefaultWireFormat().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if verification
 * succeeds, false if verification fails, or a promise rejected with Error for
 * an invalid public key type or digestAlgorithm.
 */
VerificationHelpers.verifyDataSignaturePromise = function
  (data, publicKeyOrCertificate, digestAlgorithm, wireFormat, useSync)
{
  var arg3 = digestAlgorithm;
  var arg4 = wireFormat;
  var arg5 = useSync;
  // arg3,            arg4,       arg5
  // digestAlgorithm, wireFormat, useSync
  // digestAlgorithm, wireFormat, null
  // digestAlgorithm, useSync,    null
  // digestAlgorithm, null,       null
  // wireFormat,      useSync,    null
  // wireFormat,      null,       null
  // useSync,         null,       null
  // null,            null,       null
  if (typeof arg3 === 'number')
    digestAlgorithm = arg3;
  else
    digestAlgorithm = undefined;

  if (arg3 instanceof WireFormat)
    wireFormat = arg3;
  else if (arg4 instanceof WireFormat)
    wireFormat = arg4;
  else
    wireFormat = undefined;

  if (typeof arg3 === 'boolean')
    useSync = arg3;
  else if (typeof arg4 === 'boolean')
    useSync = arg4;
  else if (typeof arg5 === 'boolean')
    useSync = arg5;
  else
    useSync = false;

  var publicKey;
  if (publicKeyOrCertificate instanceof CertificateV2) {
    try {
      publicKey = publicKeyOrCertificate.getPublicKey();
    } catch (ex) {
      return SyncPromise.resolve(false);
    }
  }
  else
    publicKey = publicKeyOrCertificate;

  var encoding = data.wireEncode(wireFormat);
  return VerificationHelpers.verifySignaturePromise
    (encoding.signedBuf(), data.getSignature().getSignature(), publicKey,
     digestAlgorithm, useSync);
};

/**
 * Verify the Interest packet using the public key, where the last two name
 * components are the SignatureInfo and signature bytes. This does not check the
 * type of public key or digest algorithm against the type of SignatureInfo such
 * as Sha256WithRsaSignature.
 * @param {Interest} interest The Interest packet to verify.
 * @param {PublicKey|Buffer|Blob|CertificateV2} publicKeyOrCertificate The
 * object containing the public key, or the public key DER which is used to make
 * the PublicKey object, or the certificate containing the public key.
 * @param {number} digestAlgorithm (optional) The digest algorithm as an int
 * from the DigestAlgorithm enum. If omitted, use DigestAlgorithm.SHA256.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the Interest packet. If omitted, use WireFormat getDefaultWireFormat().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if verification
 * succeeds, false if verification fails, or a promise rejected with Error for
 * an invalid public key type or digestAlgorithm.
 */
VerificationHelpers.verifyInterestSignaturePromise = function
  (interest, publicKeyOrCertificate, digestAlgorithm, wireFormat, useSync)
{
  var arg3 = digestAlgorithm;
  var arg4 = wireFormat;
  var arg5 = useSync;
  // arg3,            arg4,       arg5
  // digestAlgorithm, wireFormat, useSync
  // digestAlgorithm, wireFormat, null
  // digestAlgorithm, useSync,    null
  // digestAlgorithm, null,       null
  // wireFormat,      useSync,    null
  // wireFormat,      null,       null
  // useSync,         null,       null
  // null,            null,       null
  if (typeof arg3 === 'number')
    digestAlgorithm = arg3;
  else
    digestAlgorithm = undefined;

  if (arg3 instanceof WireFormat)
    wireFormat = arg3;
  else if (arg4 instanceof WireFormat)
    wireFormat = arg4;
  else
    wireFormat = undefined;

  if (typeof arg3 === 'boolean')
    useSync = arg3;
  else if (typeof arg4 === 'boolean')
    useSync = arg4;
  else if (typeof arg5 === 'boolean')
    useSync = arg5;
  else
    useSync = false;

  var publicKey;
  if (publicKeyOrCertificate instanceof CertificateV2) {
    try {
      publicKey = publicKeyOrCertificate.getPublicKey();
    } catch (ex) {
      return SyncPromise.resolve(false);
    }
  }
  else
    publicKey = publicKeyOrCertificate;

  if (wireFormat == undefined)
    wireFormat = WireFormat.getDefaultWireFormat();
  var signature = VerificationHelpers.extractSignature_(interest, wireFormat);
  if (signature == null)
    return SyncPromise.resolve(false);

  var encoding = interest.wireEncode(wireFormat);
  return VerificationHelpers.verifySignaturePromise
    (encoding.signedBuf(), signature.getSignature(), publicKey, digestAlgorithm,
     useSync);
};

/**
 * Verify the buffer against the digest using the digest algorithm.
 * @param {Buffer|Blob} buffer The input buffer to verify.
 * @param {Buffer|Blob} digest The digest bytes.
 * @param {number} digestAlgorithm The digest algorithm as an int from the
 * DigestAlgorithm enum, such as DigestAlgorithm.SHA256.
 * @return {boolean} true if verification succeeds, false if verification fails.
 * @throws Error for an invalid digestAlgorithm.
 */
VerificationHelpers.verifyDigest = function(buffer, digest, digestAlgorithm)
{
  if (buffer instanceof Blob)
    buffer = buffer.buf();
  if (digest instanceof Blob)
    digest = digest.buf();

  if (digestAlgorithm == DigestAlgorithm.SHA256) {
    var hash = Crypto.createHash('sha256');
    hash.update(buffer);
    var computedDigest = hash.digest();

    // Use a loop to compare since it handles different array types.
    if (digest.length != computedDigest.length)
      return false;
    for (var i = 0; i < digest.length; ++i) {
      if (digest[i] != computedDigest[i])
        return false;
    }
    return true;
  }
  else
    throw new Error("verifyDigest: Invalid digest algorithm");
};

/**
 * Extract the signature information from the interest name.
 * @param {Interest} interest The interest whose signature is needed.
 * @param {WireFormat} wireFormat The wire format used to decode signature
 * information from the interest name.
 * @return {Signature} The Signature object, or null if can't decode.
 */
VerificationHelpers.extractSignature_ = function(interest, wireFormat)
{
  if (interest.getName().size() < 2)
    return null;

  try {
    return wireFormat.decodeSignatureInfoAndValue
      (interest.getName().get(-2).getValue().buf(),
       interest.getName().get(-1).getValue().buf(), false);
  } catch (ex) {
    return null;
  }
};

// The first time verify is called, it sets this to determine if a signature
// buffer needs to be converted to a string for the crypto verifier.
VerificationHelpers.verifyUsesString_ = null;
VerificationHelpers.setVerifyUsesString_ = function()
{
  var hashResult = Crypto.createHash('sha256').digest();
  // If the hash result is a string, we assume that this is a version of
  //   crypto where verify also uses a string signature.
  VerificationHelpers.verifyUsesString_ = (typeof hashResult === 'string');
};

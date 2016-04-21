/**
 * Copyright (C) 2014-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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

// Use capitalized Crypto to not clash with the browser's crypto.subtle.
/** @ignore */
var Crypto = require('../../crypto.js'); /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var DataUtils = require('../../encoding/data-utils.js').DataUtils; /** @ignore */
var SecurityException = require('../security-exception.js').SecurityException; /** @ignore */
var DigestSha256Signature = require('../../digest-sha256-signature.js').DigestSha256Signature; /** @ignore */
var Sha256WithRsaSignature = require('../../sha256-with-rsa-signature.js').Sha256WithRsaSignature; /** @ignore */
var UseSubtleCrypto = require("../../use-subtle-crypto-node.js").UseSubtleCrypto;

/**
 * A PolicyManager is an abstract base class to represent the policy for
 * verifying data packets. You must create an object of a subclass.
 * @constructor
 */
var PolicyManager = function PolicyManager()
{
};

exports.PolicyManager = PolicyManager;

/**
 * Check if the received data packet or signed interest can escape from
 * verification and be trusted as valid.
 * Your derived class should override.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} True if the data or interest does not need to be verified
 * to be trusted as valid, otherwise false.
 */
PolicyManager.prototype.skipVerifyAndTrust = function(dataOrInterest)
{
  throw new Error("PolicyManager.skipVerifyAndTrust is not implemented");
};

/**
 * Check if this PolicyManager has a verification rule for the received data
 * packet or signed interest.
 * Your derived class should override.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} True if the data or interest must be verified, otherwise
 * false.
 */
PolicyManager.prototype.requireVerify = function(dataOrInterest)
{
  throw new Error("PolicyManager.requireVerify is not implemented");
};

/**
 * Check whether the received data packet complies with the verification policy,
 * and get the indication of the next verification step.
 * Your derived class should override.
 *
 * @param {Data|Interest} dataOrInterest The Data object or interest with the
 * signature to check.
 * @param {number} stepCount The number of verification steps that have been
 * done, used to track the verification progress.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(dataOrInterest).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onVerifyFailed If the signature check fails, this calls
 * onVerifyFailed(dataOrInterest).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {WireFormat} wireFormat
 * @returns {ValidationRequest} The indication of next verification step, or
 * null if there is no further step.
 */
PolicyManager.prototype.checkVerificationPolicy = function
  (dataOrInterest, stepCount, onVerified, onVerifyFailed, wireFormat)
{
  throw new Error("PolicyManager.checkVerificationPolicy is not implemented");
};

/**
 * Check if the signing certificate name and data name satisfy the signing
 * policy.
 * Your derived class should override.
 *
 * @param {Name} dataName The name of data to be signed.
 * @param {Name} certificateName The name of signing certificate.
 * @returns {boolean} True if the signing certificate can be used to sign the
 * data, otherwise false.
 */
PolicyManager.prototype.checkSigningPolicy = function(dataName, certificateName)
{
  throw new Error("PolicyManager.checkSigningPolicy is not implemented");
};

/**
 * Infer the signing identity name according to the policy. If the signing
 * identity cannot be inferred, return an empty name.
 * Your derived class should override.
 *
 * @param {Name} dataName The name of data to be signed.
 * @returns {Name} The signing identity or an empty name if cannot infer.
 */
PolicyManager.prototype.inferSigningIdentity = function(dataName)
{
  throw new Error("PolicyManager.inferSigningIdentity is not implemented");
};

// The first time verifySha256WithRsaSignature is called, it sets this to
// determine if a signature buffer needs to be converted to a string for the
// crypto verifier.
PolicyManager.verifyUsesString = null;

/**
 * Check the type of signature and use the publicKeyDer to verify the
 * signedBlob using the appropriate signature algorithm.
 * @param {Signature} signature An object of a subclass of Signature, e.g.
 * Sha256WithRsaSignature.
 * @param {SignedBlob} signedBlob the SignedBlob with the signed portion to
 * verify.
 * @param {Blob} publicKeyDer The DER-encoded public key used to verify the
 * signature.
 * @param {function} onComplete This calls onComplete(true) if the signature
 * verifies, otherwise onComplete(false).
 * @throws SecurityException if the signature type is not recognized or if
 * publicKeyDer can't be decoded.
 */
PolicyManager.verifySignature = function
  (signature, signedBlob, publicKeyDer, onComplete)
{
  if (signature instanceof Sha256WithRsaSignature) {
    if (publicKeyDer.isNull()) {
      onComplete(false);
      return;
    }
    PolicyManager.verifySha256WithRsaSignature
      (signature.getSignature(), signedBlob, publicKeyDer, onComplete);
  }
  else if (signature instanceof DigestSha256Signature)
    PolicyManager.verifyDigestSha256Signature
      (signature.getSignature(), signedBlob, onComplete);
  else
    // We don't expect this to happen.
    throw new SecurityException(new Error
      ("PolicyManager.verify: Signature type is unknown"));
};

/**
 * Verify the RSA signature on the SignedBlob using the given public key.
 * @param {Blob} signature The signature bits.
 * @param {SignedBlob} signedBlob the SignedBlob with the signed portion to
 * verify.
 * @param {Blob} publicKeyDer The DER-encoded public key used to verify the
 * signature.
 * @param {function} onComplete This calls onComplete(true) if the signature
 * verifies, otherwise onComplete(false).
 */
PolicyManager.verifySha256WithRsaSignature = function
  (signature, signedBlob, publicKeyDer, onComplete)
{
  if (UseSubtleCrypto()){
    var algo = {name:"RSASSA-PKCS1-v1_5",hash:{name:"SHA-256"}};

    crypto.subtle.importKey("spki", publicKeyDer.buf().buffer, algo, true, ["verify"]).then(function(publicKey){
      return crypto.subtle.verify(algo, publicKey, signature.buf(), signedBlob.signedBuf())
    }).then(function(verified){
      onComplete(verified);
    });
  } else {
    if (PolicyManager.verifyUsesString === null) {
      var hashResult = Crypto.createHash('sha256').digest();
      // If the hash result is a string, we assume that this is a version of
      //   crypto where verify also uses a string signature.
      PolicyManager.verifyUsesString = (typeof hashResult === 'string');
    }

    // The crypto verifier requires a PEM-encoded public key.
    var keyBase64 = publicKeyDer.buf().toString('base64');
    var keyPem = "-----BEGIN PUBLIC KEY-----\n";
    for (var i = 0; i < keyBase64.length; i += 64)
      keyPem += (keyBase64.substr(i, 64) + "\n");
    keyPem += "-----END PUBLIC KEY-----";

    var verifier = Crypto.createVerify('RSA-SHA256');
    verifier.update(signedBlob.signedBuf());
    var signatureBytes = PolicyManager.verifyUsesString ?
      DataUtils.toString(signature.buf()) : signature.buf();
    onComplete(verifier.verify(keyPem, signatureBytes));
  }
};

/**
 * Verify the DigestSha256 signature on the SignedBlob by verifying that the
 * digest of SignedBlob equals the signature.
 * @param {Blob} signature The signature bits.
 * @param {SignedBlob} signedBlob the SignedBlob with the signed portion to
 * verify.
 * @param {function} onComplete This calls onComplete(true) if the signature
 * verifies, otherwise onComplete(false).
 */
PolicyManager.verifyDigestSha256Signature = function
  (signature, signedBlob, onComplete)
{
  // Set signedPortionDigest to the digest of the signed portion of the signedBlob.
  var hash = Crypto.createHash('sha256');
  hash.update(signedBlob.signedBuf());
  var signedPortionDigest = new Blob(hash.digest(), false);

  onComplete(signedPortionDigest.equals(signature));
};

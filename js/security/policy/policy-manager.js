/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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
var Sha256WithEcdsaSignature = require('../../sha256-with-ecdsa-signature.js').Sha256WithEcdsaSignature; /** @ignore */
var VerificationHelpers = require('../verification-helpers.js').VerificationHelpers; /** @ignore */
var DigestAlgorithm = require('../security-types.js').DigestAlgorithm; /** @ignore */
var PublicKey = require('../certificate/public-key.js').PublicKey; /** @ignore */
var SyncPromise = require("../../util/sync-promise").SyncPromise;

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
 * @return {boolean} True if the data or interest does not need to be verified
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
 * @return {boolean} True if the data or interest must be verified, otherwise
 * false.
 */
PolicyManager.prototype.requireVerify = function(dataOrInterest)
{
  throw new Error("PolicyManager.requireVerify is not implemented");
};

/**
 * Check whether the received data or interest packet complies with the
 * verification policy, and get the indication of the next verification step.
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
 * @param {function} onValidationFailed If the signature check fails, this calls
 * onValidationFailed(dataOrInterest, reason).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {WireFormat} wireFormat
 * @return {ValidationRequest} The indication of next verification step, or
 * null if there is no further step.
 */
PolicyManager.prototype.checkVerificationPolicy = function
  (dataOrInterest, stepCount, onVerified, onValidationFailed, wireFormat)
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
 * @return {boolean} True if the signing certificate can be used to sign the
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
 * @return {Name} The signing identity or an empty name if cannot infer.
 */
PolicyManager.prototype.inferSigningIdentity = function(dataName)
{
  throw new Error("PolicyManager.inferSigningIdentity is not implemented");
};

// The first time verify is called, it sets this to determine if a signature
// buffer needs to be converted to a string for the crypto verifier.
PolicyManager.verifyUsesString_ = null;
PolicyManager.setVerifyUsesString_ = function()
{
  var hashResult = Crypto.createHash('sha256').digest();
  // If the hash result is a string, we assume that this is a version of
  //   crypto where verify also uses a string signature.
  PolicyManager.verifyUsesString_ = (typeof hashResult === 'string');
};

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
  if (signature instanceof Sha256WithRsaSignature ||
      signature instanceof Sha256WithEcdsaSignature) {
    if (publicKeyDer.isNull()) {
      onComplete(false);
      return;
    }

    var publicKey;
    try {
      publicKey = new PublicKey(publicKeyDer);
    } catch (ex) {
      throw new SecurityException(new Error
        ("PolicyManager.verify: Error decoding public key: " + ex));
    }

    SyncPromise.complete(onComplete,
      VerificationHelpers.verifySignaturePromise
        (signedBlob.signedBuf(), signature.getSignature(), publicKey,
         DigestAlgorithm.SHA256, !onComplete));
  }
  else if (signature instanceof DigestSha256Signature)
    onComplete(VerificationHelpers.verifyDigest
      (signedBlob.signedBuf(), signature.getSignature(),
       DigestAlgorithm.SHA256));
  else
    // We don't expect this to happen.
    throw new SecurityException(new Error
      ("PolicyManager.verify: Signature type is unknown"));
};

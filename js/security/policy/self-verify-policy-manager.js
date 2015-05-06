/**
 * Copyright (C) 2014-2015 Regents of the University of California.
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

var Name = require('../../name.js').Name;
var Interest = require('../../interest.js').Interest;
var Data = require('../../data.js').Data;
var Blob = require('../../util/blob.js').Blob;
var IdentityCertificate = require('../certificate/identity-certificate.js').IdentityCertificate;
var KeyLocator = require('../../key-locator.js').KeyLocator;
var KeyLocatorType = require('../../key-locator.js').KeyLocatorType;
var SecurityException = require('../security-exception.js').SecurityException;
var WireFormat = require('../../encoding/wire-format.js').WireFormat;
var PolicyManager = require('./policy-manager.js').PolicyManager;

/**
 * A SelfVerifyPolicyManager implements a PolicyManager to use the public key
 * DER in the data packet's KeyLocator (if available) or look in the
 * IdentityStorage for the public key with the name in the KeyLocator (if
 * available) and use it to verify the data packet, without searching a
 * certificate chain.  If the public key can't be found, the verification fails.
 *
 * @param {IdentityStorage} identityStorage (optional) The IdentityStorage for
 * looking up the public key. This object must remain valid during the life of
 * this SelfVerifyPolicyManager. If omitted, then don't look for a public key
 * with the name in the KeyLocator and rely on the KeyLocator having the full
 * public key DER.
 * @constructor
 */
var SelfVerifyPolicyManager = function SelfVerifyPolicyManager(identityStorage)
{
  // Call the base constructor.
  PolicyManager.call(this);

  this.identityStorage = identityStorage;
};

SelfVerifyPolicyManager.prototype = new PolicyManager();
SelfVerifyPolicyManager.prototype.name = "SelfVerifyPolicyManager";

exports.SelfVerifyPolicyManager = SelfVerifyPolicyManager;

/**
 * Never skip verification.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} False.
 */
SelfVerifyPolicyManager.prototype.skipVerifyAndTrust = function(dataOrInterest)
{
  return false;
};

/**
 * Always return true to use the self-verification rule for the received data.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} True.
 */
SelfVerifyPolicyManager.prototype.requireVerify = function(dataOrInterest)
{
  return true;
};

/**
 * Use the public key DER in the KeyLocator (if available) or look in the
 * IdentityStorage for the public key with the name in the KeyLocator (if
 * available) and use it to verify the data packet.  If the public key can't
   * be found, call onVerifyFailed.
 *
 * @param {Data|Interest} dataOrInterest The Data object or interest with the
 * signature to check.
 * @param {number} stepCount The number of verification steps that have been
 * done, used to track the verification progress.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(dataOrInterest).
 * @param {function} onVerifyFailed If the signature check fails, this calls
 * onVerifyFailed(dataOrInterest).
 * @param {WireFormat} wireFormat
 * @returns {ValidationRequest} null for no further step for looking up a
 * certificate chain.
 */
SelfVerifyPolicyManager.prototype.checkVerificationPolicy = function
  (dataOrInterest, stepCount, onVerified, onVerifyFailed, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  if (dataOrInterest instanceof Data) {
    var data = dataOrInterest;
    // wireEncode returns the cached encoding if available.
    this.verify(data.getSignature(), data.wireEncode(), function(verified) {
      if (verified) onVerified(data); else onVerifyFailed(data);
    });
  }
  else if (dataOrInterest instanceof Interest) {
    var interest = dataOrInterest;
    // Decode the last two name components of the signed interest
    var signature = wireFormat.decodeSignatureInfoAndValue
      (interest.getName().get(-2).getValue().buf(),
       interest.getName().get(-1).getValue().buf());

    // wireEncode returns the cached encoding if available.
    this.verify(signature, interest.wireEncode(), function(verified) {
      if (verified) onVerified(interest); else onVerifyFailed(interest);
    });
  }
  else
    throw new SecurityException(new Error
      ("checkVerificationPolicy: unrecognized type for dataOrInterest"));

  // No more steps, so return a None.
  return null;
};

/**
 * Override to always indicate that the signing certificate name and data name
 * satisfy the signing policy.
 *
 * @param {Name} dataName The name of data to be signed.
 * @param {Name} certificateName The name of signing certificate.
 * @returns {boolean} True to indicate that the signing certificate can be used
 * to sign the data.
 */
SelfVerifyPolicyManager.prototype.checkSigningPolicy = function
  (dataName, certificateName)
{
  return true;
};

/**
 * Override to indicate that the signing identity cannot be inferred.
 *
 * @param {Name} dataName The name of data to be signed.
 * @returns {Name} An empty name because cannot infer.
 */
SelfVerifyPolicyManager.prototype.inferSigningIdentity = function(dataName)
{
  return new Name();
};

/**
 * Check the type of signatureInfo to get the KeyLocator. Use the public key
 * DER in the KeyLocator (if available) or look in the IdentityStorage for the
 * public key with the name in the KeyLocator (if available) and use it to
 * verify the signedBlob. If the public key can't be found, return false.
 * (This is a generalized method which can verify both a Data packet and an
 * interest.)
 * @param {Signature} signatureInfo An object of a subclass of Signature, e.g.
 * Sha256WithRsaSignature.
 * @param {SignedBlob} signedBlob the SignedBlob with the signed portion to
 * verify.
 * @param onComplete {function} This calls onComplete(true) if the signature
 * verifies, otherwise onComplete(false).
 */
SelfVerifyPolicyManager.prototype.verify = function
  (signatureInfo, signedBlob, onComplete)
{
  var publicKeyDer;
  if (KeyLocator.canGetFromSignature(signatureInfo)) {
    publicKeyDer = this.getPublicKeyDer(KeyLocator.getFromSignature
      (signatureInfo));
    if (publicKeyDer.isNull())
      onComplete(false);
  }

  return PolicyManager.verifySignature
    (signatureInfo, signedBlob, publicKeyDer, onComplete);
};

/**
 * Return the public key DER in the KeyLocator (if available) or look in the
 * IdentityStorage for the public key with the name in the KeyLocator (if
 * available). If the public key can't be found, return and empty Blob.
 * @param {KeyLocator} keyLocator The KeyLocator.
 * @returns {Blob} The public key DER or an empty Blob if not found.
 */
SelfVerifyPolicyManager.prototype.getPublicKeyDer = function(keyLocator)
{
  if (keyLocator.getType() == KeyLocatorType.KEY)
    // Use the public key DER directly.
    return keyLocator.getKeyData();
  else if (keyLocator.getType() == KeyLocatorType.KEYNAME &&
           this.identityStorage != null)
    // Assume the key name is a certificate name.
    return this.identityStorage.getKey
      (IdentityCertificate.certificateNameToPublicKeyName
       (keyLocator.getKeyName()));
  else
    // Can't find a key to verify.
    return new Blob();
};

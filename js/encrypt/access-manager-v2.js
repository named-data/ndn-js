/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/encryptor.cpp
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
var Name = require('../name.js').Name; /** @ignore */
var Data = require('../data.js').Data; /** @ignore */
var RsaKeyParams = require('../security/key-params.js').RsaKeyParams; /** @ignore */
var KeyType = require('../security/security-types').KeyType; /** @ignore */
var SigningInfo = require('../security/signing-info.js').SigningInfo; /** @ignore */
var PublicKey = require('../security/certificate/public-key.js').PublicKey; /** @ignore */
var EncryptedContent = require('./encrypted-content.js').EncryptedContent; /** @ignore */
var EncryptAlgorithmType = require('./algo/encrypt-params.js').EncryptAlgorithmType; /** @ignore */
var InMemoryStorageRetaining = require('../in-memory-storage/in-memory-storage-retaining.js').InMemoryStorageRetaining; /** @ignore */
var NdnCommon = require('../util/ndn-common.js').NdnCommon; /** @ignore */
var EncryptorV2 = require('./encryptor-v2.js').EncryptorV2; /** @ignore */
var LOG = require('../log.js').Log.LOG;

/**
 * AccessManagerV2 controls the decryption policy by publishing granular
 * per-namespace access policies in the form of key encryption
 * (KEK, plaintext public) and key decryption (KDK, encrypted private key)
 * key pairs. This works with EncryptorV2 and DecryptorV2 using security v2.
 * For the meaning of "KDK", etc. see:
 * https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst
 * 
 * Create an AccessManagerV2 to serve the NAC public key for other data
 * producers to fetch, and to serve encrypted versions of the private keys
 * (as safe bags) for authorized consumers to fetch.
 *
 * KEK and KDK naming:
 *
 * [identity]/NAC/[dataset]/KEK            /[key-id]                           (== KEK, public key)
 *
 * [identity]/NAC/[dataset]/KDK/[key-id]   /ENCRYPTED-BY/[user]/KEY/[key-id]   (== KDK, encrypted private key)
 *
 * \_____________  ______________/
 *               \/
 *      registered with NFD
 *
 * @param {PibIdentity} identity The data owner's namespace identity. (This will
 * be used to sign the KEK and KDK.)
 * @param {Name} dataset The name of dataset that this manager is controlling.
 * @param {KeyChain} keyChain The KeyChain used to sign Data packets.
 * @param {Face} face The Face for calling registerPrefix that will be used to
 * publish the KEK and KDK Data packets.
 * @constructor
 */
var AccessManagerV2 = function AccessManagerV2(identity, dataset, keyChain, face)
{
  this.identity_ = identity;
  this.keyChain_ = keyChain;
  this.face_ = face;

  // storage_ is for the KEK and KDKs.
  this.storage_ = new InMemoryStorageRetaining()

  // The NAC identity is: <identity>/NAC/<dataset>
  // Generate the NAC key.
  // TODO: Use a Promise.
  var nacIdentity = this.keyChain_.createIdentityV2
    (new Name(identity.getName())
     .append(EncryptorV2.NAME_COMPONENT_NAC).append(dataset),
     new RsaKeyParams());
  this.nacKey_ = nacIdentity.getDefaultKey();
  if (this.nacKey_.getKeyType() != KeyType.RSA) {
    if (LOG > 3) console.log
      ("Cannot re-use existing KEK/KDK pair, as it is not an RSA key, regenerating");
    this.nacKey_ = this.keyChain_.createKey(nacIdentity, new RsaKeyParams());
  }
  var nacKeyId = this.nacKey_.getName().get(-1);

  var kekPrefix = new Name(this.nacKey_.getIdentityName())
    .append(EncryptorV2.NAME_COMPONENT_KEK);

  var kekData = new Data(this.nacKey_.getDefaultCertificate());
  kekData.setName(new Name(kekPrefix).append(nacKeyId));
  kekData.getMetaInfo().setFreshnessPeriod
    (AccessManagerV2.DEFAULT_KEK_FRESHNESS_PERIOD_MS);
  // TODO: Use a Promise.
  this.keyChain_.sign(kekData, new SigningInfo(this.identity_));
  // A KEK looks like a certificate, but doesn't have a ValidityPeriod.
  this.storage_.insert(kekData);

  var thisEncryptor = this;
  var serveFromStorage = function(prefix, interest, face, interestFilterId, filter) {
    var data = thisEncryptor.storage_.find(interest);
    if (data != null) {
      if (LOG > 3) console.log
        ("Serving " + data.getName().toUri() + " from InMemoryStorage");
      try {
        face.putData(data);
      } catch (ex) {
        console.log("AccessManagerV2: Error in Face.putData: " +
                    NdnCommon.getErrorWithStackTrace(ex));
      }
    }
    else {
      if (LOG > 3) console.log
        ("Didn't find CK data for " + interest.getName().toUri());
      // TODO: Send NACK?
    }
  };

  var onRegisterFailed = function(prefix) {
    if (LOG > 0) console.log("Failed to register prefix " + prefix.toUri());
  };

  this.kekRegisteredPrefixId_ = this.face_.registerPrefix
    (kekPrefix, serveFromStorage, onRegisterFailed);

  var kdkPrefix = new Name(this.nacKey_.getIdentityName())
    .append(EncryptorV2.NAME_COMPONENT_KDK).append(nacKeyId);
  this.kdkRegisteredPrefixId_ = this.face_.registerPrefix
    (kdkPrefix, serveFromStorage, onRegisterFailed);
};

exports.AccessManagerV2 = AccessManagerV2;

AccessManagerV2.prototype.shutdown = function()
{
  this.face_.unsetInterestFilter(this.kekRegisteredPrefixId_);
  this.face_.unsetInterestFilter(this.kdkRegisteredPrefixId_);
};

/**
 * Authorize a member identified by memberCertificate to decrypt data under
 * the policy.
 * @param {CertificateV2} memberCertificate The certificate that identifies the
 * member to authorize.
 * @return {Data} The published KDK Data packet.
 */
AccessManagerV2.prototype.addMember = function(memberCertificate)
{
  var kdkName = new Name(this.nacKey_.getIdentityName());
  kdkName
    .append(EncryptorV2.NAME_COMPONENT_KDK)
    .append(this.nacKey_.getName().get(-1)) // key-id
    .append(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY)
    .append(memberCertificate.getKeyName());

  var secretLength = 32;
  var secret = Crypto.randomBytes(secretLength);
  // To be compatible with OpenSSL which uses a null-terminated string,
  // replace each 0 with 1. And to be compatible with the Java security
  // library which interprets the secret as a char array converted to UTF8,
  // limit each byte to the ASCII range 1 to 127.
  for (var i = 0; i < secretLength; ++i) {
    if (secret[i] == 0)
      secret[i] = 1;

    secret[i] &= 0x7f;
  }

  var kdkSafeBag = this.keyChain_.exportSafeBag
    (this.nacKey_.getDefaultCertificate(), secret);

  var memberKey = new PublicKey(memberCertificate.getPublicKey());

  var encryptedContent = new EncryptedContent();
  encryptedContent.setPayload(kdkSafeBag.wireEncode());
  // Debug: Use a Promise.
  encryptedContent.setPayloadKey(memberKey.encrypt
    (secret, EncryptAlgorithmType.RsaOaep));

  var kdkData = new Data(kdkName);
  kdkData.setContent(encryptedContent.wireEncodeV2());
  // FreshnessPeriod can serve as a soft access control for revoking access.
  kdkData.getMetaInfo().setFreshnessPeriod
    (AccessManagerV2.DEFAULT_KDK_FRESHNESS_PERIOD_MS);
  // Debug: Use a Promise.
  this.keyChain_.sign(kdkData, new SigningInfo(this.identity_));

  this.storage_.insert(kdkData);

  return kdkData;
};

/**
 * Get the number of packets stored in in-memory storage.
 * @return {number} The number of packets.
 */
AccessManagerV2.prototype.size = function()
{
  return this.storage_.size();
};

AccessManagerV2.DEFAULT_KEK_FRESHNESS_PERIOD_MS = 3600 * 1000.0;
AccessManagerV2.DEFAULT_KDK_FRESHNESS_PERIOD_MS = 3600 * 1000.0;

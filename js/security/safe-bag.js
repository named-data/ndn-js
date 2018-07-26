/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/safe-bag.cpp
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
var Name = require('../name.js').Name; /** @ignore */
var Data = require('../data.js').Data; /** @ignore */
var ContentType = require('../meta-info.js').ContentType; /** @ignore */
var Sha256WithRsaSignature = require('../sha256-with-rsa-signature.js').Sha256WithRsaSignature; /** @ignore */
var Sha256WithEcdsaSignature = require('../sha256-with-ecdsa-signature.js').Sha256WithEcdsaSignature; /** @ignore */
var KeyLocator = require('../key-locator.js').KeyLocator; /** @ignore */
var KeyLocatorType = require('../key-locator.js').KeyLocatorType; /** @ignore */
var WireFormat = require('../encoding/wire-format.js').WireFormat; /** @ignore */
var DigestAlgorithm = require('./security-types.js').DigestAlgorithm; /** @ignore */
var KeyType = require('./security-types.js').KeyType; /** @ignore */
var ValidityPeriod = require('./validity-period.js').ValidityPeriod; /** @ignore */
var CertificateV2 = require('./v2/certificate-v2.js').CertificateV2; /** @ignore */
var SyncPromise = require('../util/sync-promise.js').SyncPromise; /** @ignore */
var Tpm = require('./tpm/tpm.js').Tpm; /** @ignore */
var TpmBackEndMemory = require('./tpm/tpm-back-end-memory.js').TpmBackEndMemory; /** @ignore */
var PublicKey = require('./certificate/public-key.js').PublicKey;

/**
 * A SafeBag represents a container for sensitive related information such as a
 * certificate and private key.
 *
 * There are two forms of the SafeBag constructor:
 * SafeBag(certificate, privateKeyBag) - Create a SafeBag with the given
 * certificate and private key.
 * SafeBag(keyName, privateKeyBag, publicKeyEncoding [, password,
 *         digestAlgorithm, wireFormat]) - Create a SafeBag with given private
 * key and a new self-signed certificate for the given public key.
 * @param {Data} certificate The certificate data packet (used only for
 * SafeBag(certificate, privateKeyBag)). This copies the object.
 * @param {Blob) privateKeyBag The encoded private key. If encrypted, this is a
 * PKCS #8 EncryptedPrivateKeyInfo. If not encrypted, this is an unencrypted
 * PKCS #8 PrivateKeyInfo.
 * @param {Buffer} password (optional) The password for decrypting the private
 * key in order to sign the self-signed certificate. If the password is supplied,
 * use it to decrypt the PKCS #8 EncryptedPrivateKeyInfo. If the password is
 * omitted or null, privateKeyBag is an unencrypted PKCS #8 PrivateKeyInfo.
 * @param {number} digestAlgorithm: (optional) The digest algorithm for signing
 * the self-signed certificate (as an int from the DigestAlgorithm enum). If
 * omitted, use DigestAlgorithm.SHA256 .
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the self-signed certificate in order to sign it. If omitted, use
 * WireFormat.getDefaultWireFormat().
 * @constructor
 */
var SafeBag = function SafeBag
  (keyNameOrCertificate, privateKeyBag, publicKeyEncoding, password,
   digestAlgorithm, wireFormat)
{
  if (keyNameOrCertificate instanceof Name) {
    var keyName = keyNameOrCertificate;
    if (digestAlgorithm == undefined)
      digestAlgorithm = DigestAlgorithm.SHA256;
    if (wireFormat == undefined)
      wireFormat = WireFormat.getDefaultWireFormat();

    this.certificate_ = SafeBag.makeSelfSignedCertificate_
      (keyName, privateKeyBag, publicKeyEncoding, password,
       digestAlgorithm, wireFormat);
    this.privateKeyBag_ = privateKeyBag;
  }
  else {
    // The certificate is supplied.
    this.certificate_ = new Data(keyNameOrCertificate);
    this.privateKeyBag_ = privateKeyBag;
  }
};

exports.SafeBag = SafeBag;

/**
 * Get the certificate data packet.
 * @return {Data} The certificate as a Data packet. If you need to process it
 * as a certificate object then you must create a new CertificateV2(data).
 */
SafeBag.prototype.getCertificate = function() { return this.certificate_; };

/**
 * Get the encoded private key.
 * @return {Blob} The encoded private key. If encrypted, this is a PKCS #8
 * EncryptedPrivateKeyInfo. If not encrypted, this is an unencrypted PKCS #8
 * PrivateKeyInfo.
 */
SafeBag.prototype.getPrivateKeyBag = function() { return this.privateKeyBag_; };

SafeBag.makeSelfSignedCertificate_ = function
  (keyName, privateKeyBag, publicKeyEncoding, password, digestAlgorithm,
   wireFormat)
{
  var certificate = new CertificateV2();

  // Set the name.
  var now = new Date().getTime();
  var certificateName = new Name(keyName);
  certificateName.append("self").appendVersion(now);
  certificate.setName(certificateName);

  // Set the MetaInfo.
  certificate.getMetaInfo().setType(ContentType.KEY);
  // Set a one-hour freshness period.
  certificate.getMetaInfo().setFreshnessPeriod(3600 * 1000.0);

  // Set the content.
  var publicKey = new PublicKey(publicKeyEncoding);
  certificate.setContent(publicKey.getKeyDer());

  // Create a temporary in-memory Tpm and import the private key.
  var tpm = new Tpm("", "", new TpmBackEndMemory());
  SyncPromise.complete(null,
    tpm.importPrivateKeyPromise_(keyName, privateKeyBag.buf(), password, true));

  // Set the signature info.
  if (publicKey.getKeyType() == KeyType.RSA)
    certificate.setSignature(new Sha256WithRsaSignature());
  else if (publicKey.getKeyType() == KeyType.EC)
    certificate.setSignature(new Sha256WithEcdsaSignature());
  else
    throw new Error("Unsupported key type");
  var signatureInfo = certificate.getSignature();
  KeyLocator.getFromSignature(signatureInfo).setType(KeyLocatorType.KEYNAME);
  KeyLocator.getFromSignature(signatureInfo).setKeyName(keyName);

  // Set a 20-year validity period.
  ValidityPeriod.getFromSignature(signatureInfo).setPeriod
    (now, now + 20 * 365 * 24 * 3600 * 1000.0);

  // Encode once to get the signed portion.
  var encoding = certificate.wireEncode(wireFormat);
  var signatureBytes = SyncPromise.complete(null,
    tpm.signPromise(encoding.signedBuf(), keyName, digestAlgorithm, true));
  signatureInfo.setSignature(signatureBytes);

  // Encode again to include the signature.
  certificate.wireEncode(wireFormat);

  return certificate;
};

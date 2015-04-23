/**
 * This class represents an NDN Data Signature object.
 * Copyright (C) 2014-2015 Regents of the University of California.
 * @author: Meki Cheraoui
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

var Blob = require('./util/blob.js').Blob;
var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var KeyLocator = require('./key-locator.js').KeyLocator;
var LOG = require('./log.js').Log.LOG;

/**
 * Create a new Sha256WithRsaSignature object, possibly copying values from
 * another object.
 *
 * @param {Sha256WithRsaSignature} value (optional) If value is a
 * Sha256WithRsaSignature, copy its values.  If value is omitted, the keyLocator
 * is the default with unspecified values and the signature is unspecified.
 * @constructor
 */
var Sha256WithRsaSignature = function Sha256WithRsaSignature(value)
{
  if (typeof value === 'object' && value instanceof Sha256WithRsaSignature) {
    // Copy the values.
    this.keyLocator_ = new KeyLocator(value.keyLocator_);
    this.signature_ = value.signature_;
    // witness is deprecated.
    this.witness_ = value.witness_;
    // digestAlgorithm is deprecated.
    this.digestAlgorithm_ = value.digestAlgorithm_;
  }
  else {
    this.keyLocator_ = new KeyLocator();
    this.signature_ = new Blob();
    // witness is deprecated.
    this.witness_ = null;
    // digestAlgorithm is deprecated.
    this.digestAlgorithm_ = null;
  }
};

exports.Sha256WithRsaSignature = Sha256WithRsaSignature;

/**
 * Create a new Sha256WithRsaSignature which is a copy of this object.
 * @returns {Sha256WithRsaSignature} A new object which is a copy of this object.
 */
Sha256WithRsaSignature.prototype.clone = function()
{
  return new Sha256WithRsaSignature(this);
};

/**
 * Get the key locator.
 * @returns {KeyLocator} The key locator.
 */
Sha256WithRsaSignature.prototype.getKeyLocator = function()
{
  return this.keyLocator_;
};

/**
 * Get the data packet's signature bytes.
 * @returns {Blob} The signature bytes. If not specified, the value isNull().
 */
Sha256WithRsaSignature.prototype.getSignature = function()
{
  return this.signature_;
};

/**
 * @deprecated Use getSignature. This method returns a Buffer which is the former
 * behavior of getSignature, and should only be used while updating your code.
 */
Sha256WithRsaSignature.prototype.getSignatureAsBuffer = function()
{
  return this.signature_.buf();
};

/**
 * Set the key locator to a copy of the given keyLocator.
 * @param {KeyLocator} keyLocator The KeyLocator to copy.
 */
Sha256WithRsaSignature.prototype.setKeyLocator = function(keyLocator)
{
  this.keyLocator_ = typeof keyLocator === 'object' && keyLocator instanceof KeyLocator ?
    new KeyLocator(keyLocator) : new KeyLocator();
};

/**
 * Set the data packet's signature bytes.
 * @param {Blob} signature
 */
Sha256WithRsaSignature.prototype.setSignature = function(signature)
{
  this.signature_ = typeof signature === 'object' && signature instanceof Blob ?
    signature : new Blob(signature);
};

Sha256WithRsaSignature.prototype.from_ndnb = function(decoder)
{
  decoder.readElementStartDTag(this.getElementLabel());

  if (LOG > 4) console.log('STARTED DECODING SIGNATURE');

  if (decoder.peekDTag(NDNProtocolDTags.DigestAlgorithm)) {
    if (LOG > 4) console.log('DIGIEST ALGORITHM FOUND');
    this.digestAlgorithm = decoder.readUTF8DTagElement(NDNProtocolDTags.DigestAlgorithm);
  }
  if (decoder.peekDTag(NDNProtocolDTags.Witness)) {
    if (LOG > 4) console.log('WITNESS FOUND');
    this.witness = decoder.readBinaryDTagElement(NDNProtocolDTags.Witness);
  }

  //FORCE TO READ A SIGNATURE

  if (LOG > 4) console.log('SIGNATURE FOUND');
  this.signature = decoder.readBinaryDTagElement(NDNProtocolDTags.SignatureBits);

  decoder.readElementClose();
};

Sha256WithRsaSignature.prototype.to_ndnb = function(encoder)
{
  encoder.writeElementStartDTag(this.getElementLabel());

  if (null != this.digestAlgorithm && !this.digestAlgorithm.equals(NDNDigestHelper.DEFAULT_DIGEST_ALGORITHM))
    encoder.writeDTagElement(NDNProtocolDTags.DigestAlgorithm, OIDLookup.getDigestOID(this.DigestAlgorithm));

  if (null != this.witness)
    // needs to handle null witness
    encoder.writeDTagElement(NDNProtocolDTags.Witness, this.witness);

  if (this.getSignature().size() > 0)
    encoder.writeDTagElement(NDNProtocolDTags.SignatureBits, this.signature);
  else
    encoder.writeDTagElement(NDNProtocolDTags.SignatureBits, new Buffer([]));

  encoder.writeElementClose();
};

Sha256WithRsaSignature.prototype.getElementLabel = function() { return NDNProtocolDTags.Signature; };

// Define properties so we can change member variable types and implement changeCount_.
Object.defineProperty(Sha256WithRsaSignature.prototype, "keyLocator",
  { get: function() { return this.getKeyLocator(); },
    set: function(val) { this.setKeyLocator(val); } });
/**
 * @@deprecated Use getSignature and setSignature.
 */
Object.defineProperty(Sha256WithRsaSignature.prototype, "signature",
  { get: function() { return this.getSignatureAsBuffer(); },
    set: function(val) { this.setSignature(val); } });
/**
 * @deprecated
 */
Object.defineProperty(Sha256WithRsaSignature.prototype, "witness",
  { get: function() { return this.witness_; },
    set: function(val) { this.witness_ = val; ++this.changeCount_; } });
/**
 * @deprecated
 */
Object.defineProperty(Sha256WithRsaSignature.prototype, "digestAlgorithm",
  { get: function() { return this.digestAlgorithm_; },
    set: function(val) { this.digestAlgorithm_ = val; ++this.changeCount_; } });

/**
 * Note: This Signature class is not the same as the base Signature class of
 * the Common Client Libraries API. It is a deprecated name for
 * Sha256WithRsaSignature. In the future, after we remove this deprecated class,
 * we may implement the CCL version of Signature.
 * @deprecated Use new Sha256WithRsaSignature.
 */
var Signature = function Signature
  (witnessOrSignatureObject, signature, digestAlgorithm)
{
  if (typeof witnessOrSignatureObject === 'object' &&
      witnessOrSignatureObject instanceof Sha256WithRsaSignature)
    // Call the base copy constructor.
    Sha256WithRsaSignature.call(this, witnessOrSignatureObject);
  else {
    // Call the base default constructor.
    Sha256WithRsaSignature.call(this);

    // Set the given fields (if supplied).
    if (witnessOrSignatureObject != null)
      // witness is deprecated.
      this.witness_ = witnessOrSignatureObject;
    if (signature != null)
      this.signature_ = typeof signature === 'object' && signature instanceof Blob ?
        signature : new Blob(signature);
    if (digestAlgorithm != null)
      // digestAlgorithm is deprecated.
      this.digestAlgorithm_ = digestAlgorithm;
  }
}

Signature.prototype = new Sha256WithRsaSignature();

exports.Signature = Signature;

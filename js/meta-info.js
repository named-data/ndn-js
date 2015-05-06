/**
 * This class represents an NDN Data MetaInfo object.
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

var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var Blob = require('./util/blob.js').Blob;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var KeyLocator = require('./key-locator.js').KeyLocator;
var KeyLocatorType = require('./key-locator.js').KeyLocatorType;
var Name = require('./name.js').Name;
var PublisherPublicKeyDigest = require('./publisher-public-key-digest.js').PublisherPublicKeyDigest;
var NDNTime = require('./util/ndn-time.js').NDNTime;
var globalKeyManager = require('./security/key-manager.js').globalKeyManager;
var WireFormat = require('./encoding/wire-format.js').WireFormat;
var LOG = require('./log.js').Log.LOG;

var ContentType = {
  BLOB:0,
  // ContentType DATA is deprecated.  Use ContentType.BLOB .
  DATA:0,
  LINK:1,
  KEY: 2,
  // ContentType ENCR, GONE and NACK are not supported in NDN-TLV encoding and are deprecated.
  ENCR:3,
  GONE:4,
  NACK:5
};

exports.ContentType = ContentType;

/**
 * Create a new MetaInfo with the optional values.
 * @constructor
 */
var MetaInfo = function MetaInfo(publisherOrMetaInfo, timestamp, type, locator, freshnessSeconds, finalBlockId, skipSetFields)
{
  if (typeof publisherOrMetaInfo === 'object' &&
      publisherOrMetaInfo instanceof MetaInfo) {
    // Copy values.
    var metaInfo = publisherOrMetaInfo;
    this.publisher_ = metaInfo.publisher_;
    this.timestamp_ = metaInfo.timestamp; // NDNTime // deprecated
    this.type_ = metaInfo.type_;
    this.locator_ = metaInfo.locator_ == null ?
      new KeyLocator() : new KeyLocator(metaInfo.locator_);
    this.freshnessPeriod_ = metaInfo.freshnessPeriod_;
    this.finalBlockId_ = metaInfo.finalBlockId_;
  }
  else {
    this.publisher = publisherOrMetaInfo; // deprecated
    this.timestamp = timestamp; // NDNTime // deprecated
    this.type = type == null || type < 0 ? ContentType.BLOB : type;
     // The KeyLocator in MetaInfo is deprecated. Use the one in the Signature.
    this.locator = locator == null ? new KeyLocator() : new KeyLocator(locator);
    this.freshnessSeconds = freshnessSeconds; // deprecated
    this.finalBlockID = finalBlockId; // byte array // deprecated

    if (!skipSetFields) {
      // Temporarily set ENABLE_NDNX so that setFields doesn't throw.
      var saveEnableNdnx = WireFormat.ENABLE_NDNX;
      try {
        WireFormat.ENABLE_NDNX = true;
        this.setFields();
      }
      finally {
        WireFormat.ENABLE_NDNX = saveEnableNdnx;
      }
    }
  }

  this.changeCount_ = 0;
};

exports.MetaInfo = MetaInfo;

/**
 * Get the content type.
 * @returns {number} The content type as an int from ContentType.
 */
MetaInfo.prototype.getType = function()
{
  return this.type_;
};

/**
 * Get the freshness period.
 * @returns {number} The freshness period in milliseconds, or null if not
 * specified.
 */
MetaInfo.prototype.getFreshnessPeriod = function()
{
  return this.freshnessPeriod_;
};

/**
 * Get the final block ID.
 * @returns {Name.Component} The final block ID as a Name.Component. If the
 * Name.Component getValue().size() is 0, then the final block ID is not specified.
 */
MetaInfo.prototype.getFinalBlockId = function()
{
  return this.finalBlockId_;
};

/**
 * @deprecated Use getFinalBlockId.
 */
MetaInfo.prototype.getFinalBlockID = function()
{
  return this.getFinalBlockId();
};

/**
 * @deprecated Use getFinalBlockId. This method returns a Buffer which is the former
 * behavior of getFinalBlockId, and should only be used while updating your code.
 */
MetaInfo.prototype.getFinalBlockIDAsBuffer = function()
{
  return this.finalBlockId_.getValue().buf();
};

/**
 * Set the content type.
 * @param {number} type The content type as an int from ContentType.  If null,
 * this uses ContentType.BLOB.
 */
MetaInfo.prototype.setType = function(type)
{
  this.type_ = type == null || type < 0 ? ContentType.BLOB : type;
  ++this.changeCount_;
};

/**
 * Set the freshness period.
 * @param {type} freshnessPeriod The freshness period in milliseconds, or null
 * for not specified.
 */
MetaInfo.prototype.setFreshnessPeriod = function(freshnessPeriod)
{
  // Use attribute freshnessSeconds for backwards compatibility.
  if (freshnessPeriod == null || freshnessPeriod < 0)
    this.freshnessPeriod_ = null;
  else
    this.freshnessPeriod_ = freshnessPeriod;
  ++this.changeCount_;
};

MetaInfo.prototype.setFinalBlockId = function(finalBlockId)
{
  this.finalBlockId_ = typeof finalBlockId === 'object' &&
                       finalBlockId instanceof Name.Component ?
    finalBlockId : new Name.Component(finalBlockId);
  ++this.changeCount_;
};

/**
 * @deprecated Use setFinalBlockId.
 */
MetaInfo.prototype.setFinalBlockID = function(finalBlockId)
{
  this.setFinalBlockId(finalBlockId);
};

/**
 * @deprecated This sets fields for NDNx signing. Use KeyChain.
 */
MetaInfo.prototype.setFields = function()
{
  if (!WireFormat.ENABLE_NDNX)
    throw new Error
      ("Signing with NDNx-style keys is deprecated. To enable while you upgrade your code to use KeyChain.sign, set WireFormat.ENABLE_NDNX = true");

  var key = globalKeyManager.getKey();
  this.publisher = new PublisherPublicKeyDigest(key.getKeyID());

  var d = new Date();

  var time = d.getTime();

  this.timestamp = new NDNTime(time);

  if (LOG > 4) console.log('TIME msec is');

  if (LOG > 4) console.log(this.timestamp.msec);

  //DATA
  this.type = ContentType.BLOB;

  if (LOG > 4) console.log('PUBLIC KEY TO WRITE TO DATA PACKET IS ');
  if (LOG > 4) console.log(key.publicToDER().toString('hex'));

  this.locator = new KeyLocator(key.getKeyID(), KeyLocatorType.KEY_LOCATOR_DIGEST);
  ++this.changeCount_;
};

MetaInfo.prototype.from_ndnb = function(decoder)
{
  decoder.readElementStartDTag(this.getElementLabel());

  if (decoder.peekDTag(NDNProtocolDTags.PublisherPublicKeyDigest)) {
    if (LOG > 4) console.log('DECODING PUBLISHER KEY');
    this.publisher = new PublisherPublicKeyDigest();
    this.publisher.from_ndnb(decoder);
  }

  if (decoder.peekDTag(NDNProtocolDTags.Timestamp)) {
    if (LOG > 4) console.log('DECODING TIMESTAMP');
    this.timestamp = decoder.readDateTimeDTagElement(NDNProtocolDTags.Timestamp);
  }

  if (decoder.peekDTag(NDNProtocolDTags.Type)) {
    var binType = decoder.readBinaryDTagElement(NDNProtocolDTags.Type);

    if (LOG > 4) console.log('Binary Type of of Signed Info is '+binType);

    this.type = binType;

    //TODO Implement type of Key Reading
    if (null == this.type)
      throw new Error("Cannot parse signedInfo type: bytes.");
  }
  else
    this.type = ContentType.DATA; // default

  if (decoder.peekDTag(NDNProtocolDTags.FreshnessSeconds)) {
    this.freshnessSeconds = decoder.readIntegerDTagElement(NDNProtocolDTags.FreshnessSeconds);
    if (LOG > 4) console.log('FRESHNESS IN SECONDS IS '+ this.freshnessSeconds);
  }

  if (decoder.peekDTag(NDNProtocolDTags.FinalBlockID)) {
    if (LOG > 4) console.log('DECODING FINAL BLOCKID');
    this.finalBlockID = decoder.readBinaryDTagElement(NDNProtocolDTags.FinalBlockID);
  }

  if (decoder.peekDTag(NDNProtocolDTags.KeyLocator)) {
    if (LOG > 4) console.log('DECODING KEY LOCATOR');
    this.locator = new KeyLocator();
    this.locator.from_ndnb(decoder);
  }

  decoder.readElementClose();
  ++this.changeCount_;
};

/**
 * Encode this MetaInfo in ndnb, using the given keyLocator instead of the
 * locator in this object.
 * @param {BinaryXMLEncoder} encoder The encoder.
 * @param {KeyLocator} keyLocator The key locator to use (from
 * Data.getSignatureOrMetaInfoKeyLocator).
 */
MetaInfo.prototype.to_ndnb = function(encoder, keyLocator)  {
  if (!this.validate())
    throw new Error("Cannot encode : field values missing.");

  encoder.writeElementStartDTag(this.getElementLabel());

  if (null != this.publisher) {
    // We have a publisherPublicKeyDigest, so use it.
    if (LOG > 3) console.log('ENCODING PUBLISHER KEY' + this.publisher.publisherPublicKeyDigest);
    this.publisher.to_ndnb(encoder);
  }
  else {
    if (null != keyLocator &&
        keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST &&
        !keyLocator.getKeyData().isNull() &&
        keyLocator.getKeyData().size() > 0)
      // We have a TLV-style KEY_LOCATOR_DIGEST, so encode as the
      //   publisherPublicKeyDigest.
      encoder.writeDTagElement
        (NDNProtocolDTags.PublisherPublicKeyDigest, keyLocator.getKeyData().buf());
  }

  if (null != this.timestamp)
    encoder.writeDateTimeDTagElement(NDNProtocolDTags.Timestamp, this.timestamp);

  if (null != this.type && this.type != 0)
    encoder.writeDTagElement(NDNProtocolDTags.type, this.type);

  if (null != this.freshnessSeconds)
    encoder.writeDTagElement(NDNProtocolDTags.FreshnessSeconds, this.freshnessSeconds);

  if (null != this.finalBlockID)
    encoder.writeDTagElement(NDNProtocolDTags.FinalBlockID, this.finalBlockID);

  if (null != keyLocator)
    keyLocator.to_ndnb(encoder);

  encoder.writeElementClose();
};

MetaInfo.prototype.valueToType = function()
{
  return null;
};

MetaInfo.prototype.getElementLabel = function() {
  return NDNProtocolDTags.SignedInfo;
};

/**
 * @@deprecated This is only used with to_ndnb.
 */
MetaInfo.prototype.validate = function()
{
  // We don't do partial matches any more, even though encoder/decoder
  // is still pretty generous.
  if (null == this.timestamp_)
    return false;
  return true;
};

/**
 * Get the change count, which is incremented each time this object is changed.
 * @returns {number} The change count.
 */
MetaInfo.prototype.getChangeCount = function()
{
  return this.changeCount_;
};

// Define properties so we can change member variable types and implement changeCount_.
Object.defineProperty(MetaInfo.prototype, "type",
  { get: function() { return this.getType(); },
    set: function(val) { this.setType(val); } });
/**
 * @deprecated Use getFreshnessPeriod and setFreshnessPeriod.
 */
Object.defineProperty(MetaInfo.prototype, "freshnessSeconds",
  { get: function() {
      if (this.freshnessPeriod_ == null || this.freshnessPeriod_ < 0)
        return null;
      else
        // Convert from milliseconds.
        return this.freshnessPeriod_ / 1000.0;
    },
    set: function(val) {
      if (val == null || val < 0)
        this.freshnessPeriod_ = null;
      else
        // Convert to milliseconds.
        this.freshnessPeriod_ = val * 1000.0;
      ++this.changeCount_;
    } });
/**
 * @deprecated Use KeyLocator where keyLocatorType is KEY_LOCATOR_DIGEST.
 */
Object.defineProperty(MetaInfo.prototype, "publisher",
  { get: function() { return this.publisher_; },
    set: function(val) { this.publisher_ = val; ++this.changeCount_; } });
/**
 * @deprecated Use getFinalBlockId and setFinalBlockId.
 */
Object.defineProperty(MetaInfo.prototype, "finalBlockID",
  { get: function() { return this.getFinalBlockIDAsBuffer(); },
    set: function(val) { this.setFinalBlockId(val); } });
/**
 * @deprecated
 */
Object.defineProperty(MetaInfo.prototype, "timestamp",
  { get: function() { return this.timestamp_; },
    set: function(val) { this.timestamp_ = val; ++this.changeCount_; } });
/**
 * @deprecated
 */
Object.defineProperty(MetaInfo.prototype, "locator",
  { get: function() { return this.locator_; },
    set: function(val) { this.locator_ = val; ++this.changeCount_; } });

/**
 * @deprecated Use new MetaInfo.
 */
var SignedInfo = function SignedInfo(publisherOrMetaInfo, timestamp, type, locator, freshnessSeconds, finalBlockId)
{
  // Call the base constructor.
  MetaInfo.call(this, publisherOrMetaInfo, timestamp, type, locator, freshnessSeconds, finalBlockId);
}

// Set skipSetFields true since we only need the prototype functions.
SignedInfo.prototype = new MetaInfo(null, null, null, null, null, null, true);

exports.SignedInfo = SignedInfo;

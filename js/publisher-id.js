/**
 * This class represents Publisher and PublisherType Objects
 * Copyright (C) 2013-2015 Regents of the University of California.
 * @author: Meki Cheraoui
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

var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var NDNProtocolDTagsStrings = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTagsStrings;
var DecodingException = require('./encoding/decoding-exception.js').DecodingException;

/**
 * @constructor
 */
var PublisherType = function PublisherType(tag)
{
  this.KEY = NDNProtocolDTags.PublisherPublicKeyDigest;
  this.CERTIFICATE = NDNProtocolDTags.PublisherCertificateDigest;
  this.ISSUER_KEY = NDNProtocolDTags.PublisherIssuerKeyDigest;
  this.ISSUER_CERTIFICATE = NDNProtocolDTags.PublisherIssuerCertificateDigest;

  this.Tag = tag;
};

/**
 * @deprecated Use KeyLocator getKeyData and setKeyData.
 */
var PublisherID = function PublisherID()
{
  this.PUBLISHER_ID_DIGEST_ALGORITHM = "SHA-256";
  this.PUBLISHER_ID_LEN = 256/8;

  //TODO, implement publisherID creation and key creation

  //TODO implement generatePublicKeyDigest
  this.publisherID =null;//= generatePublicKeyDigest(key);//ByteArray

  //TODO implement generate key
  //CryptoUtil.generateKeyID(PUBLISHER_ID_DIGEST_ALGORITHM, key);
  this.publisherType = null;//isIssuer ? PublisherType.ISSUER_KEY : PublisherType.KEY;//publisher Type

  this.changeCount = 0;
};

exports.PublisherID = PublisherID;

PublisherID.prototype.from_ndnb = function(decoder)
{
  // We have a choice here of one of 4 binary element types.
  var nextTag = PublisherID.peekAndGetNextDTag(decoder);

  this.publisherType = new PublisherType(nextTag);

  if (nextTag < 0)
    throw new Error("Invalid publisher ID, got unexpected type");

  this.publisherID = decoder.readBinaryDTagElement(nextTag);
  if (null == this.publisherID)
    throw new DecodingException(new Error("Cannot parse publisher ID of type : " + nextTag + "."));
  ++this.changeCount;
};

PublisherID.prototype.to_ndnb = function(encoder)
{
  if (!this.validate())
    throw new Error("Cannot encode " + this.getClass().getName() + ": field values missing.");

  encoder.writeDTagElement(this.getElementLabel(), this.publisherID);
};

/**
 * Peek the next DTag in the decoder and return it if it is a PublisherID DTag.
 * @param {BinaryXMLDecoder} decoder The BinaryXMLDecoder with the input to decode.
 * @returns {number} The PublisherID DTag or -1 if it is not one of them.
 */
PublisherID.peekAndGetNextDTag = function(decoder)
{
  if (decoder.peekDTag(NDNProtocolDTags.PublisherPublicKeyDigest))
    return             NDNProtocolDTags.PublisherPublicKeyDigest;
  if (decoder.peekDTag(NDNProtocolDTags.PublisherCertificateDigest))
    return             NDNProtocolDTags.PublisherCertificateDigest;
  if (decoder.peekDTag(NDNProtocolDTags.PublisherIssuerKeyDigest))
    return             NDNProtocolDTags.PublisherIssuerKeyDigest;
  if (decoder.peekDTag(NDNProtocolDTags.PublisherIssuerCertificateDigest))
    return             NDNProtocolDTags.PublisherIssuerCertificateDigest;

  return -1;
};

PublisherID.peek = function(/* XMLDecoder */ decoder)
{
  return PublisherID.peekAndGetNextDTag(decoder) >= 0;
};

PublisherID.prototype.getElementLabel = function()
{
  return this.publisherType.Tag;
};

PublisherID.prototype.validate = function()
{
  return null != id() && null != type();
};

/**
 * Get the change count, which is incremented each time this object is changed.
 * @returns {number} The change count.
 */
PublisherID.prototype.getChangeCount = function()
{
  return this.changeCount;
};

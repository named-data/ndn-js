/**
 * This class represents Forwarding Entries
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

var ForwardingFlags = require('./forwarding-flags.js').ForwardingFlags;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var PublisherPublicKeyDigest = require('./publisher-public-key-digest.js').PublisherPublicKeyDigest;
var Name = require('./name.js').Name;
var WireFormat = require('./encoding/wire-format.js').WireFormat;

/**
 * Create a new ForwardingEntry with the optional arguments.
 * @constructor
 * @param {String} action
 * @param {Name} prefixName
 * @param {PublisherPublicKeyDigest} ndndId
 * @param {number} faceID
 * @param {number} flags
 * @param {number} lifetime in seconds
 */
var ForwardingEntry = function ForwardingEntry(action, prefixName, ndndId, faceID, flags, lifetime)
{
  if (!WireFormat.ENABLE_NDNX)
    throw new Error
      ("ForwardingEntry is for NDNx and is deprecated. To enable while you upgrade your code to use NFD, set WireFormat.ENABLE_NDNX = true");

  this.action = action;
  this.prefixName = prefixName;
  this.ndndID = ndndId;
  this.faceID = faceID;
  this.flags = flags;
  this.lifetime = lifetime;
};

exports.ForwardingEntry = ForwardingEntry;

ForwardingEntry.prototype.from_ndnb = function(
  //XMLDecoder
  decoder)
  //throws DecodingException
{
  decoder.readElementStartDTag(this.getElementLabel());
  if (decoder.peekDTag(NDNProtocolDTags.Action))
    this.action = decoder.readUTF8DTagElement(NDNProtocolDTags.Action);
  if (decoder.peekDTag(NDNProtocolDTags.Name)) {
    this.prefixName = new Name();
    this.prefixName.from_ndnb(decoder) ;
  }
  if (decoder.peekDTag(NDNProtocolDTags.PublisherPublicKeyDigest)) {
    this.NdndId = new PublisherPublicKeyDigest();
    this.NdndId.from_ndnb(decoder);
  }
  if (decoder.peekDTag(NDNProtocolDTags.FaceID))
    this.faceID = decoder.readIntegerDTagElement(NDNProtocolDTags.FaceID);
  if (decoder.peekDTag(NDNProtocolDTags.ForwardingFlags))
    this.flags = decoder.readIntegerDTagElement(NDNProtocolDTags.ForwardingFlags);
  if (decoder.peekDTag(NDNProtocolDTags.FreshnessSeconds))
    this.lifetime = decoder.readIntegerDTagElement(NDNProtocolDTags.FreshnessSeconds);

  decoder.readElementClose();
};

ForwardingEntry.prototype.to_ndnb = function(
  //XMLEncoder
  encoder)
{
  encoder.writeElementStartDTag(this.getElementLabel());
  if (null != this.action && this.action.length != 0)
    encoder.writeDTagElement(NDNProtocolDTags.Action, this.action);
  if (null != this.prefixName)
    this.prefixName.to_ndnb(encoder);
  if (null != this.NdndId)
    this.NdndId.to_ndnb(encoder);
  if (null != this.faceID)
    encoder.writeDTagElement(NDNProtocolDTags.FaceID, this.faceID);
  if (null != this.flags)
    encoder.writeDTagElement(NDNProtocolDTags.ForwardingFlags, this.flags);
  if (null != this.lifetime)
    encoder.writeDTagElement(NDNProtocolDTags.FreshnessSeconds, this.lifetime);

  encoder.writeElementClose();
};

ForwardingEntry.prototype.getElementLabel = function() { return NDNProtocolDTags.ForwardingEntry; }

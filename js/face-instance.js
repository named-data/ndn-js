/**
 * This class represents Face Instances
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
var PublisherPublicKeyDigest = require('./publisher-public-key-digest.js').PublisherPublicKeyDigest;

/**
 * @deprecated This is only used for NDNx support which is deprecated.
 */
var FaceInstance  = function FaceInstance(action, publisherPublicKeyDigest, faceID, ipProto, host, port, multicastInterface,
    multicastTTL, freshnessSeconds)
{
  this.action = action;
  this.publisherPublicKeyDigest = publisherPublicKeyDigest;
  this.faceID = faceID;
  this.ipProto = ipProto;
  this.host = host;
  this.Port = port;
  this.multicastInterface =multicastInterface;
  this.multicastTTL =multicastTTL;
  this.freshnessSeconds = freshnessSeconds;
};

exports.FaceInstance = FaceInstance;

FaceInstance.NetworkProtocol = { TCP:6, UDP:17};

/**
 * Used by NetworkObject to decode the object from a network stream.
 */
FaceInstance.prototype.from_ndnb = function(
  //XMLDecoder
  decoder)
{
  decoder.readElementStartDTag(this.getElementLabel());

  if (decoder.peekDTag(NDNProtocolDTags.Action))
    this.action = decoder.readUTF8DTagElement(NDNProtocolDTags.Action);
  if (decoder.peekDTag(NDNProtocolDTags.PublisherPublicKeyDigest)) {
    this.publisherPublicKeyDigest = new PublisherPublicKeyDigest();
    this.publisherPublicKeyDigest.from_ndnb(decoder);
  }
  if (decoder.peekDTag(NDNProtocolDTags.FaceID))
    this.faceID = decoder.readIntegerDTagElement(NDNProtocolDTags.FaceID);
  if (decoder.peekDTag(NDNProtocolDTags.IPProto)) {
    //int
    var pI = decoder.readIntegerDTagElement(NDNProtocolDTags.IPProto);

    this.ipProto = null;

    if (FaceInstance.NetworkProtocol.TCP == pI)
      this.ipProto = FaceInstance.NetworkProtocol.TCP;
    else if (FaceInstance.NetworkProtocol.UDP == pI)
      this.ipProto = FaceInstance.NetworkProtocol.UDP;
    else
      throw new Error("FaceInstance.decoder.  Invalid NDNProtocolDTags.IPProto field: " + pI);
  }

  if (decoder.peekDTag(NDNProtocolDTags.Host))
    this.host = decoder.readUTF8DTagElement(NDNProtocolDTags.Host);
  if (decoder.peekDTag(NDNProtocolDTags.Port))
    this.Port = decoder.readIntegerDTagElement(NDNProtocolDTags.Port);
  if (decoder.peekDTag(NDNProtocolDTags.MulticastInterface))
    this.multicastInterface = decoder.readUTF8DTagElement(NDNProtocolDTags.MulticastInterface);
  if (decoder.peekDTag(NDNProtocolDTags.MulticastTTL))
    this.multicastTTL = decoder.readIntegerDTagElement(NDNProtocolDTags.MulticastTTL);
  if (decoder.peekDTag(NDNProtocolDTags.FreshnessSeconds))
    this.freshnessSeconds = decoder.readIntegerDTagElement(NDNProtocolDTags.FreshnessSeconds);

  decoder.readElementClose();
};

/**
 * Used by NetworkObject to encode the object to a network stream.
 */
FaceInstance.prototype.to_ndnb = function(
  //XMLEncoder
  encoder)
{
  encoder.writeElementStartDTag(this.getElementLabel());

  if (null != this.action && this.action.length != 0)
    encoder.writeDTagElement(NDNProtocolDTags.Action, this.action);
  if (null != this.publisherPublicKeyDigest)
    this.publisherPublicKeyDigest.to_ndnb(encoder);
  if (null != this.faceID)
    encoder.writeDTagElement(NDNProtocolDTags.FaceID, this.faceID);
  if (null != this.ipProto)
    encoder.writeDTagElement(NDNProtocolDTags.IPProto, this.ipProto);
  if (null != this.host && this.host.length != 0)
    encoder.writeDTagElement(NDNProtocolDTags.Host, this.host);
  if (null != this.Port)
    encoder.writeDTagElement(NDNProtocolDTags.Port, this.Port);
  if (null != this.multicastInterface && this.multicastInterface.length != 0)
    encoder.writeDTagElement(NDNProtocolDTags.MulticastInterface, this.multicastInterface);
  if (null !=  this.multicastTTL)
    encoder.writeDTagElement(NDNProtocolDTags.MulticastTTL, this.multicastTTL);
  if (null != this.freshnessSeconds)
    encoder.writeDTagElement(NDNProtocolDTags.FreshnessSeconds, this.freshnessSeconds);

  encoder.writeElementClose();
};

FaceInstance.prototype.getElementLabel = function()
{
  return NDNProtocolDTags.FaceInstance;
};


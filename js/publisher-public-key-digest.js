/**
 * This class represents PublisherPublicKeyDigest Objects
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
var LOG = require('./log.js').Log.LOG;

/**
 * @deprecated This is only used for NDNx support which is deprecated.
 */
var PublisherPublicKeyDigest = function PublisherPublicKeyDigest(pkd)
{
  this.PUBLISHER_ID_LEN = 512/8;
  this.publisherPublicKeyDigest = pkd;

  this.changeCount = 0;
};

exports.PublisherPublicKeyDigest = PublisherPublicKeyDigest;

PublisherPublicKeyDigest.prototype.from_ndnb = function(decoder)
{
  this.publisherPublicKeyDigest = decoder.readBinaryDTagElement(this.getElementLabel());

  if (LOG > 4) console.log('Publisher public key digest is ' + this.publisherPublicKeyDigest);

  if (null == this.publisherPublicKeyDigest)
    throw new Error("Cannot parse publisher key digest.");

  //TODO check if the length of the PublisherPublicKeyDigest is correct (Security reason)

  if (this.publisherPublicKeyDigest.length != this.PUBLISHER_ID_LEN) {
    if (LOG > 0)
      console.log('LENGTH OF PUBLISHER ID IS WRONG! Expected ' + this.PUBLISHER_ID_LEN + ", got " + this.publisherPublicKeyDigest.length);

    //this.publisherPublicKeyDigest = new PublisherPublicKeyDigest(this.PublisherPublicKeyDigest).PublisherKeyDigest;
  }
  ++this.changeCount;
};

PublisherPublicKeyDigest.prototype.to_ndnb= function(encoder)
{
  //TODO Check that the ByteArray for the key is present
  if (!this.validate())
    throw new Error("Cannot encode : field values missing.");

  if (LOG > 3) console.log('PUBLISHER KEY DIGEST IS'+this.publisherPublicKeyDigest);
  encoder.writeDTagElement(this.getElementLabel(), this.publisherPublicKeyDigest);
};

PublisherPublicKeyDigest.prototype.getElementLabel = function() { return NDNProtocolDTags.PublisherPublicKeyDigest; };

PublisherPublicKeyDigest.prototype.validate = function()
{
    return null != this.publisherPublicKeyDigest;
};

/**
 * Get the change count, which is incremented each time this object is changed.
 * @returns {number} The change count.
 */
PublisherPublicKeyDigest.prototype.getChangeCount = function()
{
  return this.changeCount;
};

/**
 * Copyright (C) 2014-2015 Regents of the University of California.
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

var ForwardingFlags = require('./forwarding-flags.js').ForwardingFlags;
var Name = require('./name.js').Name;
var WireFormat = require('./encoding/wire-format.js').WireFormat;
var Blob = require('./util/blob').Blob;

/**
 * A ControlParameters which holds a Name and other fields for a
 * ControlParameters which is used, for example, in the command interest to
 * register a prefix with a forwarder. See
 * http://redmine.named-data.net/projects/nfd/wiki/ControlCommand#ControlParameters
 * @constructor
 */
var ControlParameters = function ControlParameters()
{
  this.name = new Name();
  this.faceId = null;
  this.uri = null;
  this.localControlFeature = null;
  this.origin = null;
  this.cost = null;
  this.forwardingFlags = new ForwardingFlags();
  this.strategy = new Name();
  this.expirationPeriod = null;
};

exports.ControlParameters = ControlParameters;

/**
 * Encode this ControlParameters for a particular wire format.
 * @param {WireFormat} wireFormat (optional) A WireFormat object  used to encode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @returns {Blob} The encoded buffer in a Blob object.
 */
ControlParameters.prototype.wireEncode = function(wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  return wireFormat.encodeControlParameters(this);
};

/**
 * Decode the input using a particular wire format and update this
 * ControlParameters.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
ControlParameters.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  // If input is a blob, get its buf().
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ?
                     input.buf() : input;
  wireFormat.decodeControlParameters(this, decodeBuffer);
};

/**
 * Get the name.
 * @returns {Name} The name.
 */
ControlParameters.prototype.getName = function()
{
  return this.name;
};

/**
 * Get the face ID.
 * @returns {number} The face ID, or null if not specified.
 */
ControlParameters.prototype.getFaceId = function()
{
  return this.faceId;
};

/**
 * Get the URI.
 * @returns {string} The face URI, or null if not specified.
 */
ControlParameters.prototype.getUri = function()
{
  return this.uri;
};

/**
 * Get the local control feature value.
 * @returns {number} The local control feature value, or null if not specified.
 */
ControlParameters.prototype.getLocalControlFeature = function()
{
  return this.localControlFeature;
};

/**
 * Get the origin value.
 * @returns {number} The origin value, or null if not specified.
 */
ControlParameters.prototype.getOrigin = function()
{
  return this.origin;
};

/**
 * Get the cost value.
 * @returns {number} The cost value, or null if not specified.
 */
ControlParameters.prototype.getCost = function()
{
  return this.cost;
};

/**
 * Get the ForwardingFlags object.
 * @returns {ForwardingFlags} The ForwardingFlags object.
 */
ControlParameters.prototype.getForwardingFlags = function()
{
  return this.forwardingFlags;
};

/**
 * Get the strategy.
 * @returns {Name} The strategy or an empty Name
 */
ControlParameters.prototype.getStrategy = function()
{
  return this.strategy;
};

/**
 * Get the expiration period.
 * @returns {number} The expiration period in milliseconds, or null if not specified.
 */
ControlParameters.prototype.getExpirationPeriod = function()
{
  return this.expirationPeriod;
};

/**
 * Set the name to a copy of the given Name.
 * @param {Name} name The new Name to copy.
 */
ControlParameters.prototype.setName = function(name)
{
  this.name = typeof name === 'object' && name instanceof Name ?
              new Name(name) : new Name();
};

/**
 * Set the Face ID.
 * @param {number} faceId The new face ID, or null for not specified.
 */
ControlParameters.prototype.setFaceId = function(faceId)
{
  this.faceId = faceId;
};

/**
 * Set the URI.
 * @param {string} uri The new uri, or null for not specified.
 */
ControlParameters.prototype.setUri = function(uri)
{
  this.uri = uri;
};

/**
 * Set the local control feature value.
 * @param {number} localControlFeature The new local control feature value, or
 * null for not specified.
 */
ControlParameters.prototype.setLocalControlFeature = function(localControlFeature)
{
  this.localControlFeature = localControlFeature;
};

/**
 * Set the origin value.
 * @param {number} origin The new origin value, or null for not specified.
 */
ControlParameters.prototype.setOrigin = function(origin)
{
  this.origin = origin;
};

/**
 * Set the cost value.
 * @param {number} cost The new cost value, or null for not specified.
 */
ControlParameters.prototype.setCost = function(cost)
{
  this.cost = cost;
};

/**
 * Set the cost value.
 * @param {number} forwardingFlags The new cost value, or null for not specified.
 */
ControlParameters.prototype.setForwardingFlags = function(forwardingFlags)
{
  this.forwardingFlags =
    typeof forwardingFlags === 'object' && forwardingFlags instanceof ForwardingFlags ?
      new ForwardingFlags(forwardingFlags) : new ForwardingFlags();
};

/**
 * Set the strategy to a copy of the given Name.
 * @param {Name} name The new Name to copy, or null if not specified
 */
ControlParameters.prototype.setStrategy = function(strategy)
{
  this.strategy = typeof strategy === 'object' && strategy instanceof Name ?
              new Name(strategy) : new Name();
};

/**
 * Set the expiration period.
 * @param {number} expirationPeriod The expiration period in milliseconds, or
 * null for not specified.
 */
ControlParameters.prototype.setExpirationPeriod = function(expirationPeriod)
{
  this.expirationPeriod = expirationPeriod;
};

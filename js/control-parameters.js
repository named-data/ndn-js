/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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

/** @ignore */
var ForwardingFlags = require('./forwarding-flags.js').ForwardingFlags; /** @ignore */
var Name = require('./name.js').Name; /** @ignore */
var WireFormat = require('./encoding/wire-format.js').WireFormat; /** @ignore */
var Blob = require('./util/blob.js').Blob;

/**
 * A ControlParameters which holds a Name and other fields for a
 * ControlParameters which is used, for example, in the command interest to
 * register a prefix with a forwarder. See
 * http://redmine.named-data.net/projects/nfd/wiki/ControlCommand#ControlParameters
 * @constructor
 */
var ControlParameters = function ControlParameters(value)
{
  if (typeof value === 'object' && value instanceof ControlParameters) {
    // Make a deep copy.
    this.name = value.name == null ? null : new Name(value.name);
    this.faceId = value.faceId;
    this.uri = value.uri;
    this.localControlFeature = value.localControlFeature;
    this.origin = value.origin;
    this.cost = value.cost;
    this.forwardingFlags = new ForwardingFlags(value.forwardingFlags);
    this.strategy = new Name(value.strategy);
    this.expirationPeriod = value.expirationPeriod;
  }
  else {
    this.name = null;
    this.faceId = null;
    this.uri = '';
    this.localControlFeature = null;
    this.origin = null;
    this.cost = null;
    this.forwardingFlags = new ForwardingFlags();
    this.strategy = new Name();
    this.expirationPeriod = null;
  }
};

exports.ControlParameters = ControlParameters;

ControlParameters.prototype.clear = function()
{
  this.name = null;
  this.faceId = null;
  this.uri = '';
  this.localControlFeature = null;
  this.origin = null;
  this.cost = null;
  this.forwardingFlags = new ForwardingFlags();
  this.strategy = new Name();
  this.expirationPeriod = null;
};

/**
 * Encode this ControlParameters for a particular wire format.
 * @param {WireFormat} wireFormat (optional) A WireFormat object  used to encode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @return {Blob} The encoded buffer in a Blob object.
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
  if (typeof input === 'object' && input instanceof Blob)
    // Input is a blob, so get its buf() and set copy false.
    wireFormat.decodeControlParameters(this, input.buf(), false);
  else
    wireFormat.decodeControlParameters(this, input, true);
};

/**
 * Get the name.
 * @return {Name} The name. If not specified, return null.
 */
ControlParameters.prototype.getName = function()
{
  return this.name;
};

/**
 * Get the face ID.
 * @return {number} The face ID, or null if not specified.
 */
ControlParameters.prototype.getFaceId = function()
{
  return this.faceId;
};

/**
 * Get the URI.
 * @return {string} The face URI, or an empty string if not specified.
 */
ControlParameters.prototype.getUri = function()
{
  return this.uri;
};

/**
 * Get the local control feature value.
 * @return {number} The local control feature value, or null if not specified.
 */
ControlParameters.prototype.getLocalControlFeature = function()
{
  return this.localControlFeature;
};

/**
 * Get the origin value.
 * @return {number} The origin value, or null if not specified.
 */
ControlParameters.prototype.getOrigin = function()
{
  return this.origin;
};

/**
 * Get the cost value.
 * @return {number} The cost value, or null if not specified.
 */
ControlParameters.prototype.getCost = function()
{
  return this.cost;
};

/**
 * Get the ForwardingFlags object.
 * @return {ForwardingFlags} The ForwardingFlags object.
 */
ControlParameters.prototype.getForwardingFlags = function()
{
  return this.forwardingFlags;
};

/**
 * Get the strategy.
 * @return {Name} The strategy or an empty Name
 */
ControlParameters.prototype.getStrategy = function()
{
  return this.strategy;
};

/**
 * Get the expiration period.
 * @return {number} The expiration period in milliseconds, or null if not specified.
 */
ControlParameters.prototype.getExpirationPeriod = function()
{
  return this.expirationPeriod;
};

/**
 * Set the name.
 * @param {Name} name The name. If not specified, set to null. If specified, this
 * makes a copy of the name.
 */
ControlParameters.prototype.setName = function(name)
{
  this.name = typeof name === 'object' && name instanceof Name ?
              new Name(name) : null;
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
 * @param {string} uri The new uri, or an empty string for not specified.
 */
ControlParameters.prototype.setUri = function(uri)
{
  this.uri = uri || '';
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
 * Set the ForwardingFlags object to a copy of forwardingFlags. You can use
 * getForwardingFlags() and change the existing ForwardingFlags object.
 * @param {ForwardingFlags} forwardingFlags The new cost value, or null for not specified.
 */
ControlParameters.prototype.setForwardingFlags = function(forwardingFlags)
{
  this.forwardingFlags =
    typeof forwardingFlags === 'object' && forwardingFlags instanceof ForwardingFlags ?
      new ForwardingFlags(forwardingFlags) : new ForwardingFlags();
};

/**
 * Set the strategy to a copy of the given Name.
 * @param {Name} strategy The Name to copy, or an empty Name if not specified.
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

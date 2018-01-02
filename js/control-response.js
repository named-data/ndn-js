/**
 * Copyright (C) 2016-2018 Regents of the University of California.
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
var ControlParameters = require('./control-parameters.js').ControlParameters; /** @ignore */
var WireFormat = require('./encoding/wire-format.js').WireFormat; /** @ignore */
var Blob = require('./util/blob.js').Blob;

/**
 * A ControlResponse holds a status code, status text and other fields for a
 * ControlResponse which is used, for example, in the response from sending a
 * register prefix control command to a forwarder.
 * @see http://redmine.named-data.net/projects/nfd/wiki/ControlCommand
 * @constructor
 */
var ControlResponse = function ControlResponse(value)
{
  if (typeof value === 'object' && value instanceof ControlResponse) {
    // Make a deep copy.
    this.statusCode_ = value.statusCode_;
    this.statusText_ = value.statusText_;
    this.bodyAsControlParameters_ = value.bodyAsControlParameters_ == null ? null
      : new ControlParameters(value.bodyAsControlParameters_);
  }
  else {
    this.statusCode_ = null;
    this.statusText_ = "";
    this.bodyAsControlParameters_ = null;
  }
};

exports.ControlResponse = ControlResponse;

ControlResponse.prototype.clear = function()
{
  this.statusCode_ = null;
  this.statusText_ = "";
  this.bodyAsControlParameters_ = null;
};

/**
 * Encode this ControlResponse for a particular wire format.
 * @param {WireFormat} wireFormat (optional) A WireFormat object  used to encode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @return {Blob} The encoded buffer in a Blob object.
 */
ControlResponse.prototype.wireEncode = function(wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  return wireFormat.encodeControlResponse(this);
};

/**
 * Decode the input using a particular wire format and update this
 * ControlResponse.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
ControlResponse.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  if (typeof input === 'object' && input instanceof Blob)
    // Input is a blob, so get its buf() and set copy false.
    wireFormat.decodeControlResponse(this, input.buf(), false);
  else
    wireFormat.decodeControlResponse(this, input, true);
};

/**
 * Get the status code.
 * @return {number} The status code. If not specified, return null.
 */
ControlResponse.prototype.getStatusCode = function()
{
  return this.statusCode_;
};

/**
 * Get the status text.
 * @return {string} The status text. If not specified, return "".
 */
ControlResponse.prototype.getStatusText = function()
{
  return this.statusText_;
};

/**
 * Get the control response body as a ControlParameters.
 * @return {ControlParameters} The ControlParameters, or null if the body is not
 * specified or if it is not a ControlParameters.
 */
ControlResponse.prototype.getBodyAsControlParameters = function()
{
  return this.bodyAsControlParameters_;
};

/**
 * Set the status code.
 * @param statusCode {number} The status code. If not specified, set to null.
 * @return {ControlResponse} This ControlResponse so that you can chain calls to
 * update values.
 */
ControlResponse.prototype.setStatusCode = function(statusCode)
{
  this.statusCode_ = statusCode;
  return this;
};

/**
 * Set the status text.
 * @param statusText {string} The status text. If not specified, set to "".
 * @return {ControlResponse} This ControlResponse so that you can chain calls to
 * update values.
 */
ControlResponse.prototype.setStatusText = function(statusText)
{
  this.statusText_ = statusText || "";
  return this;
};

/**
 * Set the control response body as a ControlParameters.
 * @param {ControlParameters} controlParameters The ControlParameters for the
 * body. This makes a copy of the ControlParameters. If not specified or if the
 * body is not a ControlParameters, set to null.
 * @return {ControlResponse} This ControlResponse so that you can chain calls to
 * update values.
 */
ControlResponse.prototype.setBodyAsControlParameters = function(controlParameters)
{
  this.bodyAsControlParameters_ =
    typeof controlParameters === 'object' && controlParameters instanceof ControlParameters ?
      new ControlParameters(controlParameters) : null;
  return this;
};

/**
 * This class represents a Name as an array of components where each is a byte array.
 * Copyright (C) 2013-2018 Regents of the University of California.
 * @author: Meki Cheraoui, Jeff Thompson <jefft0@remap.ucla.edu>
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
var Blob = require('./util/blob.js').Blob; /** @ignore */
var DataUtils = require('./encoding/data-utils.js').DataUtils; /** @ignore */
var LOG = require('./log.js').Log.LOG; /** @ignore */
var DecodingException = require('./encoding/decoding-exception.js').DecodingException;

/**
 * Create a new Name from components.
 *
 * @constructor
 * @param {string|Name|Array<string|Array<number>|ArrayBuffer|Buffer|Name>} components if a string, parse it as a URI.  If a Name, add a deep copy of its components.
 * Otherwise it is an array of components which are appended according to Name.append, so
 * convert each and store it as an array of Buffer.  If a component is a string, encode as utf8.
 */
var Name = function Name(components)
{
  if (typeof components == 'string') {
    if (LOG > 3) console.log('Content Name String ' + components);
    this.components = Name.createNameArray(components);
  }
  else if (typeof components === 'object') {
    this.components = [];
    if (components instanceof Name)
      this.append(components);
    else {
      for (var i = 0; i < components.length; ++i)
        this.append(components[i]);
    }
  }
  else if (components == null)
    this.components = [];
  else
    if (LOG > 1) console.log("NO CONTENT NAME GIVEN");

  this.changeCount = 0;
};

/**
 * A ComponentType specifies the recognized types of a name component. If
 * the component type in the packet is not a recognized enum value, then we
 * use ComponentType.OTHER_CODE and you can call
 * Name.Component.getOtherTypeCode(). We do this to keep the recognized
 * component type values independent of packet encoding details.
 */
var ComponentType = {
  IMPLICIT_SHA256_DIGEST: 1,
  PARAMETERS_SHA256_DIGEST: 2,
  GENERIC: 8,
  OTHER_CODE: 0x7fff
};

exports.Name = Name;
exports.ComponentType = ComponentType;

/**
 * Create a new Name.Component with a copy of the given value.
 * (To create an ImplicitSha256Digest component, use fromImplicitSha256Digest.)
 * (To create a ParametersSha256Digest component, use fromParametersSha256Digest.)
 * @param {Name.Component|String|Array<number>|ArrayBuffer|Buffer} value If the
 * value is a string, encode it as utf8 (but don't unescape).
 * @param (number) type (optional) The component type as an int from the
 * ComponentType enum. If name component type is not a recognized ComponentType
 * enum value, then set this to ComponentType.OTHER_CODE and use the
 * otherTypeCode parameter. If omitted, use ComponentType.GENERIC.
 * @param (number) otherTypeCode (optional) If type is ComponentType.OTHER_CODE,
 * then this is the packet's unrecognized content type code, which must be
 * non-negative.
 * @constructor
 */
Name.Component = function NameComponent(value, type, otherTypeCode)
{
  if (typeof value === 'object' && value instanceof Name.Component) {
    // The copy constructor.
    this.value_ = value.value_;
    this.type_ = value.type_;
    this.otherTypeCode_ = value.otherTypeCode_;
    return;
  }

  if (!value)
    this.value_ = new Blob([]);
  else if (typeof value === 'object' && typeof ArrayBuffer !== 'undefined' &&
           value instanceof ArrayBuffer)
    // Make a copy.  Turn the value into a Uint8Array since the Buffer
    //   constructor doesn't take an ArrayBuffer.
    this.value_ = new Blob(new Buffer(new Uint8Array(value)), false);
  else if (typeof value === 'object' && value instanceof Blob)
    this.value_ = value;
  else
    // Blob will make a copy if needed.
    this.value_ = new Blob(value);

  if (type === ComponentType.OTHER_CODE) {
    if (otherTypeCode == undefined)
      throw new Error
        ("To use an other code, call Name.Component(value, ComponentType.OTHER_CODE, otherTypeCode)");

    if (otherTypeCode < 0)
      throw new Error("Name.Component other type code must be non-negative");
    this.otherTypeCode_ = otherTypeCode;
  }
  else
    this.otherTypeCode_ = -1;

  this.type_ = (type == undefined ? ComponentType.GENERIC : type);
};

/**
 * Get the component value.
 * @return {Blob} The component value.
 */
Name.Component.prototype.getValue = function()
{
  return this.value_;
};

/**
 * @deprecated Use getValue. This method returns a Buffer which is the former
 * behavior of getValue, and should only be used while updating your code.
 */
Name.Component.prototype.getValueAsBuffer = function()
{
  // Assume the caller won't modify it.
  return this.value_.buf();
};

/**
 * Get the name component type.
 * @return {number} The name component type as an int from the ComponentType
 * enum. If this is ComponentType.OTHER_CODE, then call getOtherTypeCode() to
 * get the unrecognized component type code.
 */
Name.Component.prototype.getType = function()
{
  return this.type_;
};

/**
 * Get the component type code from the packet which is other than a
 * recognized ComponentType enum value. This is only meaningful if getType()
 * is ComponentType.OTHER_CODE.
 * @return (Number) The type code.
 */
Name.Component.prototype.getOtherTypeCode = function()
{
  return this.otherTypeCode_;
};

/**
 * @deprecated Use getValue which returns a Blob.
 */
Object.defineProperty(Name.Component.prototype, "value",
  { get: function() { return this.getValueAsBuffer(); } });

/**
 * Convert this component value to a string by escaping characters according to the NDN URI Scheme.
 * This also adds "..." to a value with zero or more ".".
 * This adds a type code prefix as needed, such as "sha256digest=".
 * @return {string} The escaped string.
 */
Name.Component.prototype.toEscapedString = function()
{
  if (this.type_ === ComponentType.IMPLICIT_SHA256_DIGEST)
    return "sha256digest=" + this.value_.toHex();
  if (this.type_ === ComponentType.PARAMETERS_SHA256_DIGEST)
    return "params-sha256=" + this.value_.toHex();

  var typeString;
  if (this.type_ === ComponentType.GENERIC)
    typeString = "";
  else
    typeString = (this.type_ === ComponentType.OTHER_CODE ?
                  this.otherTypeCode_ : this.type_) + "=";

  return typeString + Name.toEscapedString(this.value_.buf());
};

/**
 * Check if this component is a segment number according to NDN naming
 * conventions for "Segment number" (marker 0x00).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * @return {number}  True if this is a segment number.
 */
Name.Component.prototype.isSegment = function()
{
  return this.value_.size() >= 1 && this.value_.buf()[0] == 0x00 &&
         this.isGeneric();
};

/**
 * Check if this component is a segment byte offset according to NDN
 * naming conventions for segment "Byte offset" (marker 0xFB).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * @return  True if this is a segment byte offset.
 */
Name.Component.prototype.isSegmentOffset = function()
{
  return this.value_.size() >= 1 && this.value_.buf()[0] == 0xFB &&
         this.isGeneric();
};

/**
 * Check if this component is a version number  according to NDN naming
 * conventions for "Versioning" (marker 0xFD).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * @return {number}  True if this is a version number.
 */
Name.Component.prototype.isVersion = function()
{
  return this.value_.size() >= 1 && this.value_.buf()[0] == 0xFD &&
         this.isGeneric();
};

/**
 * Check if this component is a timestamp  according to NDN naming
 * conventions for "Timestamp" (marker 0xFC).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * @return  True if this is a timestamp.
 */
Name.Component.prototype.isTimestamp = function()
{
  return this.value_.size() >= 1 && this.value_.buf()[0] == 0xFC &&
         this.isGeneric();
};

/**
 * Check if this component is a sequence number according to NDN naming
 * conventions for "Sequencing" (marker 0xFE).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * @return  True if this is a sequence number.
 */
Name.Component.prototype.isSequenceNumber = function()
{
  return this.value_.size() >= 1 && this.value_.buf()[0] == 0xFE &&
         this.isGeneric();
};

/**
 * Check if this component is a generic component.
 * @return {boolean} True if this is an generic component.
 */
Name.Component.prototype.isGeneric = function()
{
  return this.type_ === ComponentType.GENERIC;
};

/**
 * Check if this component is an ImplicitSha256Digest component.
 * @return {boolean} True if this is an ImplicitSha256Digest component.
 */
Name.Component.prototype.isImplicitSha256Digest = function()
{
  return this.type_ === ComponentType.IMPLICIT_SHA256_DIGEST;
};

/**
 * Check if this component is a ParametersSha256Digest component.
 * @return {boolean} True if this is a ParametersSha256Digest component.
 */
Name.Component.prototype.isParametersSha256Digest = function()
{
  return this.type_ === ComponentType.PARAMETERS_SHA256_DIGEST;
};

/**
 * Interpret this name component as a network-ordered number and return an integer.
 * @return {number} The integer number.
 */
Name.Component.prototype.toNumber = function()
{
  return DataUtils.bigEndianToUnsignedInt(this.value_.buf());
};

/**
 * Interpret this name component as a network-ordered number with a marker and
 * return an integer.
 * @param {number} marker The required first byte of the component.
 * @return {number} The integer number.
 * @throws Error If the first byte of the component does not equal the marker.
 */
Name.Component.prototype.toNumberWithMarker = function(marker)
{
  if (this.value_.size() == 0 || this.value_.buf()[0] != marker)
    throw new Error("Name component does not begin with the expected marker");

  return DataUtils.bigEndianToUnsignedInt(this.value_.buf().slice(1));
};

/**
 * Interpret this name component as a segment number according to NDN naming
 * conventions for "Segment number" (marker 0x00).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * @return {number} The integer segment number.
 * @throws Error If the first byte of the component is not the expected marker.
 */
Name.Component.prototype.toSegment = function()
{
  return this.toNumberWithMarker(0x00);
};

/**
 * Interpret this name component as a segment byte offset according to NDN
 * naming conventions for segment "Byte offset" (marker 0xFB).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * @return The integer segment byte offset.
 * @throws Error If the first byte of the component is not the expected marker.
 */
Name.Component.prototype.toSegmentOffset = function()
{
  return this.toNumberWithMarker(0xFB);
};

/**
 * Interpret this name component as a version number  according to NDN naming
 * conventions for "Versioning" (marker 0xFD). Note that this returns
 * the exact number from the component without converting it to a time
 * representation.
 * @return {number} The integer version number.
 * @throws Error If the first byte of the component is not the expected marker.
 */
Name.Component.prototype.toVersion = function()
{
  return this.toNumberWithMarker(0xFD);
};

/**
 * Interpret this name component as a timestamp  according to NDN naming
 * conventions for "Timestamp" (marker 0xFC).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * @return The number of microseconds since the UNIX epoch (Thursday,
 * 1 January 1970) not counting leap seconds.
 * @throws Error If the first byte of the component is not the expected marker.
 */
Name.Component.prototype.toTimestamp = function()
{
  return this.toNumberWithMarker(0xFC);
};

/**
 * Interpret this name component as a sequence number according to NDN naming
 * conventions for "Sequencing" (marker 0xFE).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * @return The integer sequence number.
 * @throws Error If the first byte of the component is not the expected marker.
 */
Name.Component.prototype.toSequenceNumber = function()
{
  return this.toNumberWithMarker(0xFE);
};

/**
 * Create a component whose value is the nonNegativeInteger encoding of the
 * number.
 * @param {number} number The number to be encoded.
 * @param (number) type (optional) The component type as an int from the
 * ComponentType enum. If name component type is not a recognized ComponentType
 * enum value, then set this to ComponentType.OTHER_CODE and use the
 * otherTypeCode parameter. If omitted, use ComponentType.GENERIC.
 * @param (number) otherTypeCode (optional) If type is ComponentType.OTHER_CODE,
 * then this is the packet's unrecognized content type code, which must be
 * non-negative.
 * @return {Name.Component} The new component value.
 */
Name.Component.fromNumber = function(number, type, otherTypeCode)
{
  var encoder = new TlvEncoder(8);
  encoder.writeNonNegativeInteger(number);
  return new Name.Component
    (new Blob(encoder.getOutput(), false), type, otherTypeCode);
};

/**
 * Create a component whose value is the marker appended with the
 * nonNegativeInteger encoding of the number.
 * @param {number} number
 * @param {number} marker
 * @return {Name.Component}
 */
Name.Component.fromNumberWithMarker = function(number, marker)
{
  var encoder = new TlvEncoder(9);
  // Encode backwards.
  encoder.writeNonNegativeInteger(number);
  encoder.writeNonNegativeInteger(marker);
  return new Name.Component(new Blob(encoder.getOutput(), false));
};

/**
 * Create a component with the encoded segment number according to NDN
 * naming conventions for "Segment number" (marker 0x00).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * param {number} segment The segment number.
 * returns {Name.Component} The new Component.
 */
Name.Component.fromSegment = function(segment)
{
  return Name.Component.fromNumberWithMarker(segment, 0x00);
};

/**
 * Create a component with the encoded segment byte offset according to NDN
 * naming conventions for segment "Byte offset" (marker 0xFB).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * param {number} segmentOffset The segment byte offset.
 * returns {Name.Component} The new Component.
 */
Name.Component.fromSegmentOffset = function(segmentOffset)
{
  return Name.Component.fromNumberWithMarker(segmentOffset, 0xFB);
};

/**
 * Create a component with the encoded version number according to NDN
 * naming conventions for "Versioning" (marker 0xFD).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * Note that this encodes the exact value of version without converting from a
 * time representation.
 * param {number} version The version number.
 * returns {Name.Component} The new Component.
 */
Name.Component.fromVersion = function(version)
{
  return Name.Component.fromNumberWithMarker(version, 0xFD);
};

/**
 * Create a component with the encoded timestamp according to NDN naming
 * conventions for "Timestamp" (marker 0xFC).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * param {number} timestamp The number of microseconds since the UNIX epoch (Thursday,
 * 1 January 1970) not counting leap seconds.
 * returns {Name.Component} The new Component.
 */
Name.Component.fromTimestamp = function(timestamp)
{
  return Name.Component.fromNumberWithMarker(timestamp, 0xFC);
};

/**
 * Create a component with the encoded sequence number according to NDN naming
 * conventions for "Sequencing" (marker 0xFE).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * param {number} sequenceNumber The sequence number.
 * returns {Name.Component} The new Component.
 */
Name.Component.fromSequenceNumber = function(sequenceNumber)
{
  return Name.Component.fromNumberWithMarker(sequenceNumber, 0xFE);
};

/**
 * Create a component of type ImplicitSha256DigestComponent, so that
 * isImplicitSha256Digest() is true.
 * @param {Blob|Buffer} digest The SHA-256 digest value.
 * @return {Name.Component} The new Component.
 * @throws DecodingException If the digest length is not 32 bytes.
 */
Name.Component.fromImplicitSha256Digest = function(digest)
{
  digestBlob = typeof digest === 'object' && digest instanceof Blob ?
    digest : new Blob(digest, true);
  if (digestBlob.size() !== 32)
    throw new DecodingException
      ("Name.Component.fromImplicitSha256Digest: The digest length must be 32 bytes");

  var result = new Name.Component(digestBlob);
  result.type_ = ComponentType.IMPLICIT_SHA256_DIGEST;
  return result;
};

/**
 * Create a component of type ParametersSha256DigestComponent, so that
 * isParametersSha256Digest() is true.
 * @param {Blob|Buffer} digest The SHA-256 digest value.
 * @return {Name.Component} The new Component.
 * @throws DecodingException If the digest length is not 32 bytes.
 */
Name.Component.fromParametersSha256Digest = function(digest)
{
  digestBlob = typeof digest === 'object' && digest instanceof Blob ?
    digest : new Blob(digest, true);
  if (digestBlob.size() !== 32)
    throw new DecodingException
      ("Name.Component.fromParametersSha256Digest: The digest length must be 32 bytes");

  var result = new Name.Component(digestBlob);
  result.type_ = ComponentType.PARAMETERS_SHA256_DIGEST;
  return result;
};

/**
 * Get the successor of this component, as described in Name.getSuccessor.
 * @return {Name.Component} A new Name.Component which is the successor of this.
 */
Name.Component.prototype.getSuccessor = function()
{
  // Allocate an extra byte in case the result is larger.
  var result = new Buffer(this.value_.size() + 1);

  var carry = true;
  for (var i = this.value_.size() - 1; i >= 0; --i) {
    if (carry) {
      result[i] = (this.value_.buf()[i] + 1) & 0xff;
      carry = (result[i] === 0);
    }
    else
      result[i] = this.value_.buf()[i];
  }

  if (carry)
    // Assume all the bytes were set to zero (or the component was empty). In
    // NDN ordering, carry does not mean to prepend a 1, but to make a component
    // one byte longer of all zeros.
    result[result.length - 1] = 0;
  else
    // We didn't need the extra byte.
    result = result.slice(0, this.value_.size());

  return new Name.Component
    (new Blob(result, false), this.type_, this.otherTypeCode_);
};

/**
 * Check if this is the same component as other.
 * @param {Name.Component} other The other Component to compare with.
 * @return {Boolean} true if the components are equal, otherwise false.
 */
Name.Component.prototype.equals = function(other)
{
  if (!(typeof other === 'object' && other instanceof Name.Component))
    return false;

  if (this.type_ === ComponentType.OTHER_CODE)
    return this.value_.equals(other.value_) &&
      other.type_ === ComponentType.OTHER_CODE &&
      this.otherTypeCode_ == other.otherTypeCode_;
  else
    return this.value_.equals(other.value_) && this.type_ === other.type_;
};

/**
 * Compare this to the other Component using NDN canonical ordering.
 * @param {Name.Component} other The other Component to compare with.
 * @return {number} 0 if they compare equal, -1 if this comes before other in
 * the canonical ordering, or 1 if this comes after other in the canonical
 * ordering.
 *
 * @see http://named-data.net/doc/0.2/technical/CanonicalOrder.html
 */
Name.Component.prototype.compare = function(other)
{
  var myTypeCode = (this.type_ === ComponentType.OTHER_CODE ?
                    this.otherTypeCode_ : this.type_);
  var otherTypeCode = (other.type_ === ComponentType.OTHER_CODE ?
                       other.otherTypeCode_ : other.type_);

  if (myTypeCode < otherTypeCode)
    return -1;
  if (myTypeCode > otherTypeCode)
    return 1;

  return Name.Component.compareBuffers(this.value_.buf(), other.value_.buf());
};

/**
 * Do the work of Name.Component.compare to compare the component buffers.
 * @param {Buffer} component1
 * @param {Buffer} component2
 * @return {number} 0 if they compare equal, -1 if component1 comes before
 * component2 in the canonical ordering, or 1 if component1 comes after
 * component2 in the canonical ordering.
 */
Name.Component.compareBuffers = function(component1, component2)
{
  if (component1.length < component2.length)
    return -1;
  if (component1.length > component2.length)
    return 1;

  for (var i = 0; i < component1.length; ++i) {
    if (component1[i] < component2[i])
      return -1;
    if (component1[i] > component2[i])
      return 1;
  }

  return 0;
};

/**
 * @deprecated Use toUri.
 */
Name.prototype.getName = function()
{
  return this.toUri();
};

/** Parse uri as a URI and return an array of Buffer components.
 */
Name.createNameArray = function(uri)
{
  uri = uri.trim();
  if (uri.length <= 0)
    return [];

  var iColon = uri.indexOf(':');
  if (iColon >= 0) {
    // Make sure the colon came before a '/'.
    var iFirstSlash = uri.indexOf('/');
    if (iFirstSlash < 0 || iColon < iFirstSlash)
      // Omit the leading protocol such as ndn:
      uri = uri.substr(iColon + 1, uri.length - iColon - 1).trim();
  }

  if (uri[0] == '/') {
    if (uri.length >= 2 && uri[1] == '/') {
      // Strip the authority following "//".
      var iAfterAuthority = uri.indexOf('/', 2);
      if (iAfterAuthority < 0)
        // Unusual case: there was only an authority.
        return [];
      else
        uri = uri.substr(iAfterAuthority + 1, uri.length - iAfterAuthority - 1).trim();
    }
    else
      uri = uri.substr(1, uri.length - 1).trim();
  }

  var array = uri.split('/');

  // Unescape the components.
  var sha256digestPrefix = "sha256digest=";
  var paramsSha256Prefix = "params-sha256=";
  for (var i = 0; i < array.length; ++i) {
    var componentString = array[i];
    var component;
    if (componentString.substr(0, sha256digestPrefix.length) == sha256digestPrefix) {
      var hexString = componentString.substr(sha256digestPrefix.length).trim();
      component = Name.Component.fromImplicitSha256Digest
        (new Blob(new Buffer(hexString, 'hex')), false);
    }
    else if (componentString.substr(0, paramsSha256Prefix.length) == paramsSha256Prefix) {
      var hexString = componentString.substr(paramsSha256Prefix.length).trim();
      component = Name.Component.fromParametersSha256Digest
        (new Blob(new Buffer(hexString, 'hex')), false);
    }
    else {
      var type = ComponentType.GENERIC;
      var otherTypeCode = -1;

      // Check for a component type.
      var iTypeCodeEnd = componentString.indexOf("=");
      if (iTypeCodeEnd >= 0) {
        var typeString = componentString.substring(0, iTypeCodeEnd);
        otherTypeCode = parseInt(typeString);
        if (isNaN(otherTypeCode))
          throw new Error
            ("Can't parse decimal Name Component type: " + typeString +
             " in URI " + uri);
        // Allow for a decimal value of recognized component types.
        if (otherTypeCode == ComponentType.GENERIC ||
            otherTypeCode == ComponentType.IMPLICIT_SHA256_DIGEST ||
            otherTypeCode == ComponentType.PARAMETERS_SHA256_DIGEST)
          // The enum values are the same as the TLV type codes.
          type = otherTypeCode;
        else
          type = ComponentType.OTHER_CODE;

        componentString = componentString.substring(iTypeCodeEnd + 1);
      }

      component = new Name.Component
        (Name.fromEscapedString(componentString), type, otherTypeCode);
    }

    if (component.getValue().isNull()) {
      // Ignore the illegal componenent.  This also gets rid of a trailing '/'.
      array.splice(i, 1);
      --i;
      continue;
    }
    else
      array[i] = component;
  }

  return array;
};

/**
 * Parse the uri according to the NDN URI Scheme and set the name with the
 * components.
 * @param {string} uri The URI string.
 */
Name.prototype.set = function(uri)
{
  this.components = Name.createNameArray(uri);
  ++this.changeCount;
};

/**
 * Convert the component to a Buffer and append a component to this Name.
 * (To append an ImplicitSha256Digest component, use appendImplicitSha256Digest.)
 * (To append a ParametersSha256Digest component, use appendParametersSha256Digest.)
 * @param {Name.Component|String|Array<number>|ArrayBuffer|Buffer|Name} component
 * If a component is a string, encode as utf8 (but don't unescape).
 * @param (number) type (optional) The component type as an int from the
 * ComponentType enum. If name component type is not a recognized ComponentType
 * enum value, then set this to ComponentType.OTHER_CODE and use the
 * otherTypeCode parameter. If omitted, use ComponentType.GENERIC. If the
 * component param is a Name or another Name.Component, then this is ignored.
 * @param (number) otherTypeCode (optional) If type is ComponentType.OTHER_CODE,
 * then this is the packet's unrecognized content type code, which must be
 * non-negative. If the component param is a Name or another Name.Component,
 * then this is ignored.
 * @return {Name} This name so that you can chain calls to append.
 */
Name.prototype.append = function(component, type, otherTypeCode)
{
  if (typeof component == 'object' && component instanceof Name) {
    var components;
    if (component == this)
      // special case, when we need to create a copy
      components = this.components.slice(0, this.components.length);
    else
      components = component.components;

    for (var i = 0; i < components.length; ++i)
      this.components.push(new Name.Component(components[i]));
  }
  else if (typeof component === 'object' && component instanceof Name.Component)
    // The Component is immutable, so use it as is.
    this.components.push(component);
  else
    // Just use the Name.Component constructor.
    this.components.push(new Name.Component(component, type, otherTypeCode));

  ++this.changeCount;
  return this;
};

/**
 * @deprecated Use append.
 */
Name.prototype.add = function(component)
{
  return this.append(component);
};

/**
 * Clear all the components.
 */
Name.prototype.clear = function()
{
  this.components = [];
  ++this.changeCount;
};

/**
 * Return the escaped name string according to NDN URI Scheme.
 * @param {boolean} includeScheme (optional) If true, include the "ndn:" scheme
 * in the URI, e.g. "ndn:/example/name". If false, just return the path, e.g.
 * "/example/name". If ommitted, then just return the path which is the default
 * case where toUri() is used for display.
 * @return {String}
 */
Name.prototype.toUri = function(includeScheme)
{
  if (this.size() == 0)
    return includeScheme ? "ndn:/" : "/";

  var result = includeScheme ? "ndn:" : "";

  for (var i = 0; i < this.size(); ++i)
    result += "/"+ this.components[i].toEscapedString();

  return result;
};

/**
 * @deprecated Use toUri.
 */
Name.prototype.to_uri = function()
{
  return this.toUri();
};

Name.prototype.toString = function() { return this.toUri(); }

/**
 * Append a component with the encoded segment number according to NDN
 * naming conventions for "Segment number" (marker 0x00).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * @param {number} segment The segment number.
 * @return {Name} This name so that you can chain calls to append.
 */
Name.prototype.appendSegment = function(segment)
{
  return this.append(Name.Component.fromSegment(segment));
};

/**
 * Append a component with the encoded segment byte offset according to NDN
 * naming conventions for segment "Byte offset" (marker 0xFB).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * @param {number} segmentOffset The segment byte offset.
 * @return {Name} This name so that you can chain calls to append.
 */
Name.prototype.appendSegmentOffset = function(segmentOffset)
{
  return this.append(Name.Component.fromSegmentOffset(segmentOffset));
};

/**
 * Append a component with the encoded version number according to NDN
 * naming conventions for "Versioning" (marker 0xFD).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * Note that this encodes the exact value of version without converting from a time representation.
 * @param {number} version The version number.
 * @return {Name} This name so that you can chain calls to append.
 */
Name.prototype.appendVersion = function(version)
{
  return this.append(Name.Component.fromVersion(version));
};

/**
 * Append a component with the encoded timestamp according to NDN naming
 * conventions for "Timestamp" (marker 0xFC).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * @param {number} timestamp The number of microseconds since the UNIX epoch (Thursday,
 * 1 January 1970) not counting leap seconds.
 * @return This name so that you can chain calls to append.
 */
Name.prototype.appendTimestamp = function(timestamp)
{
  return this.append(Name.Component.fromTimestamp(timestamp));
};

/**
 * Append a component with the encoded sequence number according to NDN naming
 * conventions for "Sequencing" (marker 0xFE).
 * http://named-data.net/doc/tech-memos/naming-conventions.pdf
 * @param {number} sequenceNumber The sequence number.
 * @return This name so that you can chain calls to append.
 */
Name.prototype.appendSequenceNumber = function(sequenceNumber)
{
  return this.append(Name.Component.fromSequenceNumber(sequenceNumber));
};

/**
 * Append a component of type ImplicitSha256DigestComponent, so that
 * isImplicitSha256Digest() is true.
 * @param {Blob|Buffer} digest The SHA-256 digest value.
 * @return This name so that you can chain calls to append.
 * @throws DecodingException If the digest length is not 32 bytes.
 */
Name.prototype.appendImplicitSha256Digest = function(digest)
{
  return this.append(Name.Component.fromImplicitSha256Digest(digest));
};

/**
 * Append a component of type ParametersSha256DigestComponent, so that
 * isParametersSha256Digest() is true.
 * @param {Blob|Buffer} digest The SHA-256 digest value.
 * @return This name so that you can chain calls to append.
 * @throws DecodingException If the digest length is not 32 bytes.
 */
Name.prototype.appendParametersSha256Digest = function(digest)
{
  return this.append(Name.Component.fromParametersSha256Digest(digest));
};

/**
 * @deprecated Use appendSegment.
 */
Name.prototype.addSegment = function(number)
{
  return this.appendSegment(number);
};

/**
 * Get a new name, constructed as a subset of components.
 * @param {number} iStartComponent The index if the first component to get. If
 * iStartComponent is -N then return return components starting from
 * name.size() - N.
 * @param {number} (optional) nComponents The number of components starting at
 * iStartComponent. If omitted or greater than the size of this name, get until
 * the end of the name.
 * @return {Name} A new name.
 */
Name.prototype.getSubName = function(iStartComponent, nComponents)
{
  if (iStartComponent < 0)
    iStartComponent = this.components.length - (-iStartComponent);

  if (nComponents == undefined)
    nComponents = this.components.length - iStartComponent;

  var result = new Name();

  var iEnd = iStartComponent + nComponents;
  for (var i = iStartComponent; i < iEnd && i < this.components.length; ++i)
    result.components.push(this.components[i]);

  return result;
};

/**
 * Return a new Name with the first nComponents components of this Name.
 * @param {number} nComponents The number of prefix components.  If nComponents is -N then return the prefix up
 * to name.size() - N. For example getPrefix(-1) returns the name without the final component.
 * @return {Name} A new name.
 */
Name.prototype.getPrefix = function(nComponents)
{
  if (nComponents < 0)
    return this.getSubName(0, this.components.length + nComponents);
  else
    return this.getSubName(0, nComponents);
};

/**
 * @deprecated Use getPrefix(-nComponents).
 */
Name.prototype.cut = function(nComponents)
{
  return new Name(this.components.slice(0, this.components.length - nComponents));
};

/**
 * Return the number of name components.
 * @return {number}
 */
Name.prototype.size = function()
{
  return this.components.length;
};

/**
 * Get a Name Component by index number.
 * @param {Number} i The index of the component, starting from 0.  However, if i is negative, return the component
 * at size() - (-i).
 * @return {Name.Component} The name component at the index. You must not
 * change the returned Name.Component object.
 */
Name.prototype.get = function(i)
{
  if (i >= 0) {
    if (i >= this.components.length)
      throw new Error("Name.get: Index is out of bounds");

    return this.components[i];
  }
  else {
    // Negative index.
    if (i < -this.components.length)
      throw new Error("Name.get: Index is out of bounds");

    return this.components[this.components.length - (-i)];
  }
};

/**
 * @deprecated Use size().
 */
Name.prototype.getComponentCount = function()
{
  return this.components.length;
};

/**
 * @deprecated To get just the component value array, use get(i).getValue().buf().
 */
Name.prototype.getComponent = function(i)
{
  return new Buffer(this.components[i].getValue().buf());
};

/**
 * The "file name" in a name is the last component that isn't blank and doesn't start with one of the
 *   special marker octets (for version, etc.).  Return the index in this.components of
 *   the file name, or -1 if not found.
 */
Name.prototype.indexOfFileName = function()
{
  for (var i = this.size() - 1; i >= 0; --i) {
    var component = this.components[i].getValue().buf();
    if (component.length <= 0)
      continue;

    if (component[0] == 0 || component[0] == 0xC0 || component[0] == 0xC1 ||
        (component[0] >= 0xF5 && component[0] <= 0xFF))
      continue;

    return i;
  }

  return -1;
};

/**
 * Encode this Name for a particular wire format.
 * @param {WireFormat} wireFormat (optional) A WireFormat object  used to encode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @return {Blob} The encoded buffer in a Blob object.
 */
Name.prototype.wireEncode = function(wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  return wireFormat.encodeName(this);
};

/**
 * Decode the input using a particular wire format and update this Name.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
Name.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  if (typeof input === 'object' && input instanceof Blob)
    // Input is a blob, so get its buf() and set copy false.
    wireFormat.decodeName(this, input.buf(), false);
  else
    wireFormat.decodeName(this, input, true);
};

/**
 * Compare this to the other Name using NDN canonical ordering.  If the first
 * components of each name are not equal, this returns -1 if the first comes
 * before the second using the NDN canonical ordering for name components, or 1
 * if it comes after. If they are equal, this compares the second components of
 * each name, etc.  If both names are the same up to the size of the shorter
 * name, this returns -1 if the first name is shorter than the second or 1 if it
 * is longer. For example, std::sort gives: /a/b/d /a/b/cc /c /c/a /bb .  This
 * is intuitive because all names with the prefix /a are next to each other.
 * But it may be also be counter-intuitive because /c comes before /bb according
 * to NDN canonical ordering since it is shorter.
 * The first form of compare is simply compare(other). The second form is
 * compare(iStartComponent, nComponents, other [, iOtherStartComponent] [, nOtherComponents])
 * which is equivalent to
 * self.getSubName(iStartComponent, nComponents).compare
 * (other.getSubName(iOtherStartComponent, nOtherComponents)) .
 * @param {number} iStartComponent The index if the first component of this name
 * to get. If iStartComponent is -N then compare components starting from
 * name.size() - N.
 * @param {number} nComponents The number of components starting at
 * iStartComponent. If greater than the size of this name, compare until the end
 * of the name.
 * @param {Name} other The other Name to compare with.
 * @param {number} iOtherStartComponent (optional) The index if the first
 * component of the other name to compare. If iOtherStartComponent is -N then
 * compare components starting from other.size() - N. If omitted, compare
 * starting from index 0.
 * @param {number} nOtherComponents (optional) The number of components
 * starting at iOtherStartComponent. If omitted or greater than the size of this
 * name, compare until the end of the name.
 * @return {number} 0 If they compare equal, -1 if self comes before other in
 * the canonical ordering, or 1 if self comes after other in the canonical
 * ordering.
 * @see http://named-data.net/doc/0.2/technical/CanonicalOrder.html
 */
Name.prototype.compare = function
  (iStartComponent, nComponents, other, iOtherStartComponent, nOtherComponents)
{
  if (iStartComponent instanceof Name) {
    // compare(other)
    other = iStartComponent;
    iStartComponent = 0;
    nComponents = this.size();
  }

  if (iOtherStartComponent == undefined)
    iOtherStartComponent = 0;
  if (nOtherComponents == undefined)
    nOtherComponents = other.size();

  if (iStartComponent < 0)
    iStartComponent = this.size() - (-iStartComponent);
  if (iOtherStartComponent < 0)
    iOtherStartComponent = other.size() - (-iOtherStartComponent);

  nComponents = Math.min(nComponents, this.size() - iStartComponent);
  nOtherComponents = Math.min(nOtherComponents, other.size() - iOtherStartComponent);

  var count = Math.min(nComponents, nOtherComponents);
  for (var i = 0; i < count; ++i) {
    var comparison = this.components[iStartComponent + i].compare
      (other.components[iOtherStartComponent + i]);
    if (comparison == 0)
      // The components at this index are equal, so check the next components.
      continue;

    // Otherwise, the result is based on the components at this index.
    return comparison;
  }

  // The components up to min(this.size(), other.size()) are equal, so the
  // shorter name is less.
  if (nComponents < nOtherComponents)
    return -1;
  else if (nComponents > nOtherComponents)
    return 1;
  else
    return 0;
};

/**
 * Return true if this Name has the same components as name.
 */
Name.prototype.equals = function(name)
{
  if (this.components.length != name.components.length)
    return false;

  // Start from the last component because they are more likely to differ.
  for (var i = this.components.length - 1; i >= 0; --i) {
    if (!this.components[i].equals(name.components[i]))
      return false;
  }

  return true;
};

/**
 * @deprecated Use equals.
 */
Name.prototype.equalsName = function(name)
{
  return this.equals(name);
};

/**
 * Find the last component in name that has a ContentDigest and return the digest value as Buffer,
 *   or null if not found.  See Name.getComponentContentDigestValue.
 */
Name.prototype.getContentDigestValue = function()
{
  for (var i = this.size() - 1; i >= 0; --i) {
    var digestValue = Name.getComponentContentDigestValue(this.components[i]);
    if (digestValue != null)
      return digestValue;
  }

  return null;
};

/**
 * If component is a ContentDigest, return the digest value as a Buffer slice (don't modify!).
 * If not a ContentDigest, return null.
 * A ContentDigest component is Name.ContentDigestPrefix + 32 bytes + Name.ContentDigestSuffix.
 */
Name.getComponentContentDigestValue = function(component)
{
  if (typeof component == 'object' && component instanceof Name.Component)
    component = component.getValue().buf();

  var digestComponentLength = Name.ContentDigestPrefix.length + 32 + Name.ContentDigestSuffix.length;
  // Check for the correct length and equal ContentDigestPrefix and ContentDigestSuffix.
  if (component.length == digestComponentLength &&
      DataUtils.arraysEqual(component.slice(0, Name.ContentDigestPrefix.length),
                            Name.ContentDigestPrefix) &&
      DataUtils.arraysEqual(component.slice
         (component.length - Name.ContentDigestSuffix.length, component.length),
                            Name.ContentDigestSuffix))
   return component.slice(Name.ContentDigestPrefix.length, Name.ContentDigestPrefix.length + 32);
 else
   return null;
};

// Meta GUID "%C1.M.G%C1" + ContentDigest with a 32 byte BLOB.
Name.ContentDigestPrefix = new Buffer([0xc1, 0x2e, 0x4d, 0x2e, 0x47, 0xc1, 0x01, 0xaa, 0x02, 0x85]);
Name.ContentDigestSuffix = new Buffer([0x00]);


/**
 * Return value as an escaped string according to NDN URI Scheme.
 * We can't use encodeURIComponent because that doesn't encode all the
 * characters we want to.
 * This does not add a type code prefix such as "sha256digest=".
 * @param {Buffer|Name.Component} value The value or Name.Component to escape.
 * @return {string} The escaped string.
 */
Name.toEscapedString = function(value)
{
  if (typeof value == 'object' && value instanceof Name.Component)
    value = value.getValue().buf();
  else if (typeof value === 'object' && value instanceof Blob)
    value = value.buf();

  var result = "";
  var gotNonDot = false;
  for (var i = 0; i < value.length; ++i) {
    if (value[i] != 0x2e) {
      gotNonDot = true;
      break;
    }
  }
  if (!gotNonDot) {
    // Special case for component of zero or more periods.  Add 3 periods.
    result = "...";
    for (var i = 0; i < value.length; ++i)
      result += ".";
  }
  else {
    for (var i = 0; i < value.length; ++i) {
      var x = value[i];
      // Check for 0-9, A-Z, a-z, (+), (-), (.), (_)
      if (x >= 0x30 && x <= 0x39 || x >= 0x41 && x <= 0x5a ||
          x >= 0x61 && x <= 0x7a || x == 0x2b || x == 0x2d ||
          x == 0x2e || x == 0x5f)
        result += String.fromCharCode(x);
      else
        result += "%" + (x < 16 ? "0" : "") + x.toString(16).toUpperCase();
    }
  }
  return result;
};

/**
 * Make a blob value by decoding the escapedString according to NDN URI Scheme.
 * If escapedString is "", "." or ".." then return null, which means to skip the
 * component in the name.
 * This does not check for a type code prefix such as "sha256digest=".
 * @param {string} escapedString The escaped string to decode.
 * @return {Blob} The unescaped Blob value. If the escapedString is not a valid
 * escaped component, then the Blob isNull().
 */
Name.fromEscapedString = function(escapedString)
{
  var value = unescape(escapedString.trim());

  if (value.match(/[^.]/) == null) {
    // Special case for value of only periods.
    if (value.length <= 2)
      // Zero, one or two periods is illegal.  Ignore this componenent to be
      //   consistent with the C implementation.
      return new Blob();
    else
      // Remove 3 periods.
      return new Blob
        (DataUtils.toNumbersFromString(value.substr(3, value.length - 3)), false);
  }
  else
    return new Blob(DataUtils.toNumbersFromString(value), false);
};

/**
 * @deprecated Use fromEscapedString. This method returns a Buffer which is the former
 * behavior of fromEscapedString, and should only be used while updating your code.
 */
Name.fromEscapedStringAsBuffer = function(escapedString)
{
  return Name.fromEscapedString(escapedString).buf();
};

/**
 * Get the successor of this name which is defined as follows.
 *
 *     N represents the set of NDN Names, and X,Y ∈ N.
 *     Operator < is defined by the NDN canonical order on N.
 *     Y is the successor of X, if (a) X < Y, and (b) ∄ Z ∈ N s.t. X < Z < Y.
 *
 * In plain words, the successor of a name is the same name, but with its last
 * component advanced to a next possible value.
 *
 * Examples:
 *
 * - The successor of / is /sha256digest=0000000000000000000000000000000000000000000000000000000000000000
 * - The successor of /%00%01/%01%02 is /%00%01/%01%03
 * - The successor of /%00%01/%01%FF is /%00%01/%02%00
 * - The successor of /%00%01/%FF%FF is /%00%01/%00%00%00
 *
 * @return {Name} A new name which is the successor of this.
 */
Name.prototype.getSuccessor = function()
{
  if (this.size() == 0)
    return new Name("/sha256digest=0000000000000000000000000000000000000000000000000000000000000000");
  else
    return this.getPrefix(-1).append(this.get(-1).getSuccessor());
};

/**
 * Return true if the N components of this name are the same as the first N
 * components of the given name.
 * @param {Name} name The name to check.
 * @return {Boolean} true if this matches the given name. This always returns
 * true if this name is empty.
 */
Name.prototype.match = function(name)
{
  var i_name = this.components;
  var o_name = name.components;

  // This name is longer than the name we are checking it against.
  if (i_name.length > o_name.length)
    return false;

  // Check if at least one of given components doesn't match. Check from last to
  // first since the last components are more likely to differ.
  for (var i = i_name.length - 1; i >= 0; --i) {
    if (!i_name[i].equals(o_name[i]))
      return false;
  }

  return true;
};

/**
 * Return true if the N components of this name are the same as the first N
 * components of the given name.
 * @param {Name} name The name to check.
 * @return {Boolean} true if this matches the given name. This always returns
 * true if this name is empty.
 */
Name.prototype.isPrefixOf = function(name) { return this.match(name); }

/**
 * Get the change count, which is incremented each time this object is changed.
 * @return {number} The change count.
 */
Name.prototype.getChangeCount = function()
{
  return this.changeCount;
};

// Put these requires at the bottom to avoid circular references.
var TlvEncoder = require('./encoding/tlv/tlv-encoder.js').TlvEncoder;
var WireFormat = require('./encoding/wire-format.js').WireFormat;

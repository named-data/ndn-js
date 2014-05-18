/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui, Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 * This class represents a Name as an array of components where each is a byte array.
 */
 
var Blob = require('./util/blob.js').Blob;
var DataUtils = require('./encoding/data-utils.js').DataUtils;
var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var LOG = require('./log.js').Log.LOG;

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
};

exports.Name = Name;

/**
 * 
 * @constructor
 * Create a new Name.Component with a copy of the given value.
 * @param {Name.Component|String|Array<number>|ArrayBuffer|Buffer} value If the value is a string, encode it as utf8 (but don't unescape).
 */
Name.Component = function NameComponent(value) 
{
  if (typeof value === 'string')
    this.value = DataUtils.stringToUtf8Array(value);
  else if (typeof value === 'object' && value instanceof Name.Component)
    this.value = new Buffer(value.value);
  else if (typeof value === 'object' && value instanceof Blob)
    this.value = new Buffer(value.buf());
  else if (typeof value === 'object' && value instanceof Buffer)
    this.value = new Buffer(value);
  else if (typeof value === 'object' && typeof ArrayBuffer !== 'undefined' &&  value instanceof ArrayBuffer) {
    // Make a copy.  Don't use ArrayBuffer.slice since it isn't always supported.                                                      
    this.value = new Buffer(new ArrayBuffer(value.byteLength));
    this.value.set(new Buffer(value));
  }
  else if (typeof value === 'object')
    // Assume value is a byte array.  We can't check instanceof Array because
    //   this doesn't work in JavaScript if the array comes from a different module.
    this.value = new Buffer(value);
  else if (!value)
    this.value = new Buffer(0);
  else 
    throw new Error("Name.Component constructor: Invalid type");
}

/**
 * Get the component value.
 * @returns {Buffer} The component value.
 */
Name.Component.prototype.getValue = function() 
{
  return this.value;
}

/**
 * Convert this component value to a string by escaping characters according to the NDN URI Scheme.
 * This also adds "..." to a value with zero or more ".".
 * @returns {string} The escaped string.
 */
Name.Component.prototype.toEscapedString = function() 
{
  return Name.toEscapedString(this.value);
}

/**
 * Check if this is the same component as other.
 * @param {Name.Component} other The other Component to compare with.
 * @returns {Boolean} true if the components are equal, otherwise false.
 */
Name.Component.prototype.equals = function(other) 
{
  return DataUtils.arraysEqual(this.value, other.value);
}

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
  for (var i = 0; i < array.length; ++i) {
    var value = Name.fromEscapedString(array[i]);
        
    if (value == null) {
      // Ignore the illegal componenent.  This also gets rid of a trailing '/'.
      array.splice(i, 1);
      --i;  
      continue;
    }
    else
      array[i] = new Name.Component(value);
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
}
  
Name.prototype.from_ndnb = function(/*XMLDecoder*/ decoder)  
{
  decoder.readElementStartDTag(this.getElementLabel());
    
  this.components = [];

  while (decoder.peekDTag(NDNProtocolDTags.Component))
    this.append(decoder.readBinaryDTagElement(NDNProtocolDTags.Component));
    
  decoder.readElementClose();
};

Name.prototype.to_ndnb = function(/*XMLEncoder*/ encoder)  
{    
  if (this.components == null) 
    throw new Error("CANNOT ENCODE EMPTY CONTENT NAME");

  encoder.writeElementStartDTag(this.getElementLabel());
  var count = this.size();
  for (var i=0; i < count; i++)
    encoder.writeDTagElement(NDNProtocolDTags.Component, this.components[i].getValue());
  
  encoder.writeElementClose();
};

Name.prototype.getElementLabel = function() 
{
  return NDNProtocolDTags.Name;
};

/**
 * Convert the component to a Buffer and append to this Name.
 * Return this Name object to allow chaining calls to add.
 * @param {Name.Component|String|Array<number>|ArrayBuffer|Buffer|Name} component If a component is a string, encode as utf8 (but don't unescape).
 * @returns {Name}
 */
Name.prototype.append = function(component) 
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
  else
    // Just use the Name.Component constructor.
    this.components.push(new Name.Component(component));

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
};

/**
 * Return the escaped name string according to "NDNx URI Scheme".
 * @returns {String}
 */
Name.prototype.toUri = function() 
{  
  if (this.size() == 0)
    return "/";
    
  var result = "";
  
  for (var i = 0; i < this.size(); ++i)
    result += "/"+ Name.toEscapedString(this.components[i].getValue());
  
  return result;  
};

/**
 * @deprecated Use toUri.
 */
Name.prototype.to_uri = function() 
{
  return this.toUri();
};

/**
 * Append a component with the encoded segment number.
 * @param {number} segment The segment number.
 * @returns {Name} This name so that you can chain calls to append.
 */
Name.prototype.appendSegment = function(segment) 
{
  var segmentNumberBigEndian = DataUtils.nonNegativeIntToBigEndian(segment);
  // Put a 0 byte in front.
  var segmentNumberComponent = new Buffer(segmentNumberBigEndian.length + 1);
  segmentNumberComponent[0] = 0;
  segmentNumberBigEndian.copy(segmentNumberComponent, 1);

  this.components.push(new Name.Component(segmentNumberComponent));
  return this;
};

/**
 * Append a component with the encoded version number.
 * Note that this encodes the exact value of version without converting from a 
 * time representation.
 * @param {number} version The version number.
 * @returns {Name} This name so that you can chain calls to append.
 */
Name.prototype.appendVersion = function(version) 
{
  var segmentNumberBigEndian = DataUtils.nonNegativeIntToBigEndian(version);
  // Put a 0 byte in front.
  var segmentNumberComponent = new Buffer(segmentNumberBigEndian.length + 1);
  segmentNumberComponent[0] = 0xfD;
  segmentNumberBigEndian.copy(segmentNumberComponent, 1);

  this.components.push(new Name.Component(segmentNumberComponent));
  return this;
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
 * @param {number} iStartComponent The index if the first component to get.
 * @param {number} (optional) nComponents The number of components starting at iStartComponent.  If omitted,
 * return components starting at iStartComponent until the end of the name.
 * @returns {Name} A new name.
 */
Name.prototype.getSubName = function(iStartComponent, nComponents)
{
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
 * @returns {Name} A new name.
 */
Name.prototype.getPrefix = function(nComponents) 
{
  if (nComponents < 0)
    return this.getSubName(0, this.components.length + nComponents);
  else
    return this.getSubName(0, nComponents);
};

/**
 * @brief Get prefix of the name, containing less minusComponents right components
 * @param minusComponents number of components to cut from the back
 */
Name.prototype.cut = function(minusComponents) 
{
  return new Name(this.components.slice(0, this.components.length - minusComponents));
};

/**
 * Return the number of name components.
 * @returns {number}
 */
Name.prototype.size = function() 
{
  return this.components.length;
};

/**
 * Return a new Name.Component of the component at the given index.  To get just the component value, use get(i).getValue().
 * @param {Number} i The index of the component, starting from 0.  However, if i is negative, return the component
 * at size() - (-i).
 * @returns {Name.Component}
 */
Name.prototype.get = function(i) 
{
  if (i >= 0) {
    if (i >= this.components.length)
      throw new Error("Name.get: Index is out of bounds");

    return new Name.Component(this.components[i]);
  }
  else {
    // Negative index.
    if (i < -this.components.length)
      throw new Error("Name.get: Index is out of bounds");

    return new Name.Component(this.components[this.components.length - (-i)]);
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
 * @deprecated To get just the component value, use get(i).getValue().
 */
Name.prototype.getComponent = function(i) 
{
  return new Buffer(this.components[i].getValue());
};

/**
 * The "file name" in a name is the last component that isn't blank and doesn't start with one of the
 *   special marker octets (for version, etc.).  Return the index in this.components of
 *   the file name, or -1 if not found.
 */
Name.prototype.indexOfFileName = function() 
{
  for (var i = this.size() - 1; i >= 0; --i) {
    var component = this.components[i].getValue();
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
    component = component.getValue();

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
 * Return value as an escaped string according to "NDNx URI Scheme".
 * We can't use encodeURIComponent because that doesn't encode all the characters we want to.
 * @param {Buffer|Name.Component} component The value or Name.Component to escape.
 * @returns {string} The escaped string.
 */
Name.toEscapedString = function(value) 
{
  if (typeof value == 'object' && value instanceof Name.Component)
    value = value.getValue();
  
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
 * Return a Buffer byte array by decoding the escapedString according to "NDNx URI Scheme".
 * If escapedString is "", "." or ".." then return null, which means to skip the component in the name.
 * @param {string} escapedString The escaped string to decode.
 * @returns {Buffer} The byte array, or null which means to skip the component in the name.
 */
Name.fromEscapedString = function(escapedString) 
{
  var value = unescape(escapedString.trim());
        
  if (value.match(/[^.]/) == null) {
    // Special case for value of only periods.  
    if (value.length <= 2)
      // Zero, one or two periods is illegal.  Ignore this componenent to be
      //   consistent with the C implementation.
      return null;
    else
      // Remove 3 periods.
      return DataUtils.toNumbersFromString(value.substr(3, value.length - 3));
  }
  else
    return DataUtils.toNumbersFromString(value);
};

/**
 * Return true if the N components of this name are the same as the first N components of the given name.
 * @param {Name} name The name to check.
 * @returns {Boolean} true if this matches the given name.  This always returns true if this name is empty.
 */
Name.prototype.match = function(name) 
{
  var i_name = this.components;
  var o_name = name.components;

  // This name is longer than the name we are checking it against.
  if (i_name.length > o_name.length)
    return false;

  // Check if at least one of given components doesn't match.
  for (var i = 0; i < i_name.length; ++i) {
    if (!i_name[i].equals(o_name[i]))
      return false;
  }

  return true;
};

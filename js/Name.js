/**
 * @author: Meki Cheraoui, Jeff Thompson
 * See COPYING for copyright and distribution information.
 * This class represents a Name as an array of components where each is a byte array.
 */
 
var DataUtils = require('./encoding/DataUtils.js').DataUtils;
var BinaryXMLEncoder = require('./encoding/BinaryXMLEncoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./encoding/BinaryXMLDecoder.js').BinaryXMLDecoder;
var NDNProtocolDTags = require('./util/NDNProtocolDTags.js').NDNProtocolDTags;
var LOG = require('./Log.js').Log.LOG;

/**
 * Create a new Name from components.
 * 
 * @constructor
 * @param {String|Name|Array<String|Array<number>|ArrayBuffer|Buffer|Name>} components if a string, parse it as a URI.  If a Name, add a deep copy of its components.  
 * Otherwise it is an array of components where each is a string, byte array, ArrayBuffer, Buffer or Name.
 * Convert each and store as an array of Buffer.  If a component is a string, encode as utf8.
 */
var Name = function Name(components) {
	if( typeof components == 'string') {		
		if(LOG>3)console.log('Content Name String '+components);
		this.components = Name.createNameArray(components);
	}
	else if(typeof components === 'object'){		
		this.components = [];
    if (components instanceof Name)
      this.append(components);
    else {
      for (var i = 0; i < components.length; ++i)
        this.append(components[i]);
    }
	}
	else if(components==null)
		this.components =[];
	else
		if(LOG>1)console.log("NO CONTENT NAME GIVEN");
};

Name.prototype.getName = function() {
    return this.to_uri();
};

exports.Name = Name;

/** Parse uri as a URI and return an array of Buffer components.
 */
Name.createNameArray = function(uri) {
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
        var component = Name.fromEscapedString(array[i]);
        
        if (component == null) {
            // Ignore the illegal componenent.  This also gets rid of a trailing '/'.
            array.splice(i, 1);
            --i;  
            continue;
        }
        else
            array[i] = component;
    }

	return array;
}


Name.prototype.from_ndnb = function(/*XMLDecoder*/ decoder)  {
		decoder.readStartElement(this.getElementLabel());

		
		this.components = new Array(); //new ArrayList<byte []>();

		while (decoder.peekStartElement(NDNProtocolDTags.Component)) {
			this.append(decoder.readBinaryElement(NDNProtocolDTags.Component));
		}
		
		decoder.readEndElement();
};

Name.prototype.to_ndnb = function(/*XMLEncoder*/ encoder)  {
		
		if( this.components ==null ) 
			throw new Error("CANNOT ENCODE EMPTY CONTENT NAME");

		encoder.writeStartElement(this.getElementLabel());
		var count = this.components.length;
		for (var i=0; i < count; i++) {
			encoder.writeElement(NDNProtocolDTags.Component, this.components[i]);
		}
		encoder.writeEndElement();
};

Name.prototype.getElementLabel = function(){
	return NDNProtocolDTags.Name;
};

/**
 * Convert the component to a Buffer and append to this Name.
 * Return this Name object to allow chaining calls to add.
 * @param {String|Array<number>|ArrayBuffer|Buffer|Name} component If a component is a string, encode as utf8.
 * @returns {Name}
 */
Name.prototype.append = function(component){
  var result;
  if (typeof component == 'string')
    result = DataUtils.stringToUtf8Array(component);
	else if (typeof component == 'object' && component instanceof Buffer)
    result = new Buffer(component);
  else if (typeof component == 'object' && typeof ArrayBuffer != 'undefined' &&  component instanceof ArrayBuffer) {
    // Make a copy.  Don't use ArrayBuffer.slice since it isn't always supported.                                                      
    result = new Buffer(new ArrayBuffer(component.byteLength));
    result.set(new Buffer(component));
  }
  else if (typeof component == 'object' && component instanceof Name) {
    var components;
    if (component == this)
      // special case, when we need to create a copy
      components = this.components.slice(0, this.components.length);
    else
      components = component.components;
      
    for (var i = 0; i < components.length; ++i)
      this.components.push(new Buffer(components[i]));
    return this;
  }
	else if(typeof component == 'object')
        // Assume component is a byte array.  We can't check instanceof Array because
        //   this doesn't work in JavaScript if the array comes from a different module.
        result = new Buffer(component);
	else 
		throw new Error("Cannot add Name element at index " + this.components.length + 
            ": Invalid type");
    
    this.components.push(result);
	return this;
};

/**
 * @deprecated Use append.
 */
Name.prototype.add = function(component)
{
  return this.append(component);
}

/**
 * Return the escaped name string according to "NDNx URI Scheme".
 * @returns {String}
 */
Name.prototype.to_uri = function() {	
    if (this.components.length == 0)
        return "/";
    
	var result = "";
	
	for(var i = 0; i < this.components.length; ++i)
		result += "/"+ Name.toEscapedString(this.components[i]);
	
	return result;	
};

/**
 * Append a component that represents a segment number
 *
 * This component has a special format handling:
 * - if number is zero, then %00 is added
 * - if number is between 1 and 255, %00%01 .. %00%FF is added
 * - ...
 * @param {number} number the segment number (integer is expected)
 * @returns {Name}
 */
Name.prototype.appendSegment = function(number) {
    var segmentNumberBigEndian = DataUtils.nonNegativeIntToBigEndian(number);
    // Put a 0 byte in front.
    var segmentNumberComponent = new Buffer(segmentNumberBigEndian.length + 1);
    segmentNumberComponent[0] = 0;
    segmentNumberBigEndian.copy(segmentNumberComponent, 1);

    this.components.push(segmentNumberComponent);
    return this;
};

/**
 * @deprecated Use appendSegment.
 */
Name.prototype.addSegment = function(number) 
{
  return this.appendSegment(number);
}
/**
 * Return a new Name with the first nComponents components of this Name.
 */
Name.prototype.getPrefix = function(nComponents) {
    return new Name(this.components.slice(0, nComponents));
}

/**
 * @brief Get prefix of the name, containing less minusComponents right components
 * @param minusComponents number of components to cut from the back
 */
Name.prototype.cut = function (minusComponents) {
    return new Name(this.components.slice(0, this.components.length-1));
}

/**
 * Return the number of name components.
 * @returns {number}
 */
Name.prototype.getComponentCount = function() {
  return this.components.length;
}

/**
 * Return a new Buffer of the component at i.
 */
Name.prototype.getComponent = function(i) {
    return new Buffer(this.components[i]);
}

/**
 * The "file name" in a name is the last component that isn't blank and doesn't start with one of the
 *   special marker octets (for version, etc.).  Return the index in this.components of
 *   the file name, or -1 if not found.
 */
Name.prototype.indexOfFileName = function() {
    for (var i = this.components.length - 1; i >= 0; --i) {
        var component = this.components[i];
        if (component.length <= 0)
            continue;
        
        if (component[0] == 0 || component[0] == 0xC0 || component[0] == 0xC1 || 
            (component[0] >= 0xF5 && component[0] <= 0xFF))
            continue;
        
        return i;
    }
    
    return -1;
}

/**
 * Return true if this Name has the same components as name.
 */
Name.prototype.equalsName = function(name) {
    if (this.components.length != name.components.length)
        return false;
    
    // Start from the last component because they are more likely to differ.
    for (var i = this.components.length - 1; i >= 0; --i) {
        if (!DataUtils.arraysEqual(this.components[i], name.components[i]))
            return false;
    }
    
    return true;
}

/**
 * Find the last component in name that has a ContentDigest and return the digest value as Buffer, 
 *   or null if not found.  See Name.getComponentContentDigestValue.
 */
Name.prototype.getContentDigestValue = function() {
    for (var i = this.components.length - 1; i >= 0; --i) {
        var digestValue = Name.getComponentContentDigestValue(this.components[i]);
        if (digestValue != null)
           return digestValue;
    }
    
    return null;
}

/**
 * If component is a ContentDigest, return the digest value as a Buffer slice (don't modify!).
 * If not a ContentDigest, return null.
 * A ContentDigest component is Name.ContentDigestPrefix + 32 bytes + Name.ContentDigestSuffix.
 */
Name.getComponentContentDigestValue = function(component) {
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
}

// Meta GUID "%C1.M.G%C1" + ContentDigest with a 32 byte BLOB. 
Name.ContentDigestPrefix = new Buffer([0xc1, 0x2e, 0x4d, 0x2e, 0x47, 0xc1, 0x01, 0xaa, 0x02, 0x85]);
Name.ContentDigestSuffix = new Buffer([0x00]);

/**
 * Return component as an escaped string according to "NDNx URI Scheme".
 * We can't use encodeURIComponent because that doesn't encode all the characters we want to.
 */
Name.toEscapedString = function(component) {
    var result = "";
    var gotNonDot = false;
    for (var i = 0; i < component.length; ++i) {
        if (component[i] != 0x2e) {
            gotNonDot = true;
            break;
        }
    }
    if (!gotNonDot) {
        // Special case for component of zero or more periods.  Add 3 periods.
        result = "...";
        for (var i = 0; i < component.length; ++i)
            result += ".";
    }
    else {
        for (var i = 0; i < component.length; ++i) {
            var x = component[i];
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
 * Return component as a Buffer by decoding the escapedString according to "NDNx URI Scheme".
 * If escapedString is "", "." or ".." then return null, which means to skip the component in the name.
 */
Name.fromEscapedString = function(escapedString) {
    var component = unescape(escapedString.trim());
        
    if (component.match(/[^.]/) == null) {
        // Special case for component of only periods.  
        if (component.length <= 2)
            // Zero, one or two periods is illegal.  Ignore this componenent to be
            //   consistent with the C implementation.
            return null;
        else
            // Remove 3 periods.
            return DataUtils.toNumbersFromString(component.substr(3, component.length - 3));
    }
    else
        return DataUtils.toNumbersFromString(component);
}

/**
 * Return true if the N components of this name are the same as the first N components of the given name.
 * @param {Name} name The name to check.
 * @returns {Boolean} true if this matches the given name.  This always returns true if this name is empty.
 */
Name.prototype.match = function(name) {
	var i_name = this.components;
	var o_name = name.components;

	// This name is longer than the name we are checking it against.
	if (i_name.length > o_name.length)
    return false;

	// Check if at least one of given components doesn't match.
  for (var i = 0; i < i_name.length; ++i) {
    if (!DataUtils.arraysEqual(i_name[i], o_name[i]))
      return false;
  }

	return true;
};

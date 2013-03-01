/**
 * @author: Meki Cheraoui, Jeff Thompson
 * See COPYING for copyright and distribution information.
 * This class represents a Name as an array of components where each is a byte array.
 */
 
/*
 * Create a new Name from _components.
 * If _components is a string, parse it as a URI.
 * If _components is a Name, add a deep copy of its components.
 * Otherwise it is an array of components where each is a string, byte array, ArrayBuffer, Uint8Array
 *   or Name. 
 * Convert and store as an array of Uint8Array.
 * If a component is a string, encode as utf8.
 */
var Name = function Name(_components){
	if( typeof _components == 'string') {		
		if(LOG>3)console.log('Content Name String '+_components);
		this.components = Name.createNameArray(_components);
	}
	else if(typeof _components === 'object'){		
		this.components = [];
        if (_components instanceof Name)
            this.add(_components);
        else {
            for (var i = 0; i < _components.length; ++i)
                this.add(_components[i]);
        }
	}
	else if(_components==null)
		this.components =[];
	else
		if(LOG>1)console.log("NO CONTENT NAME GIVEN");
};

Name.prototype.getName = function() {
    return this.to_uri();
};

/* Parse name as a URI and return an array of Uint8Array components.
 *
 */
Name.createNameArray = function(name) {
    name = name.trim();
    if (name.length <= 0)
        return [];

    var iColon = name.indexOf(':');
    if (iColon >= 0) {
        // Make sure the colon came before a '/'.
        var iFirstSlash = name.indexOf('/');
        if (iFirstSlash < 0 || iColon < iFirstSlash)
            // Omit the leading protocol such as ndn:
            name = name.substr(iColon + 1, name.length - iColon - 1).trim();
    }
    
  	if (name[0] == '/') {
        if (name.length >= 2 && name[1] == '/') {
            // Strip the authority following "//".
            var iAfterAuthority = name.indexOf('/', 2);
            if (iAfterAuthority < 0)
                // Unusual case: there was only an authority.
                return [];
            else
                name = name.substr(iAfterAuthority + 1, name.length - iAfterAuthority - 1).trim();
        }
        else
            name = name.substr(1, name.length - 1).trim();
    }

	var array = name.split('/');
    
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


Name.prototype.from_ccnb = function(/*XMLDecoder*/ decoder)  {
		decoder.readStartElement(this.getElementLabel());

		
		this.components = new Array(); //new ArrayList<byte []>();

		while (decoder.peekStartElement(CCNProtocolDTags.Component)) {
			this.add(decoder.readBinaryElement(CCNProtocolDTags.Component));
		}
		
		decoder.readEndElement();
};

Name.prototype.to_ccnb = function(/*XMLEncoder*/ encoder)  {
		
		if( this.components ==null ) 
			throw new Error("CANNOT ENCODE EMPTY CONTENT NAME");

		encoder.writeStartElement(this.getElementLabel());
		var count = this.components.length;
		for (var i=0; i < count; i++) {
			encoder.writeElement(CCNProtocolDTags.Component, this.components[i]);
		}
		encoder.writeEndElement();
};

Name.prototype.getElementLabel = function(){
	return CCNProtocolDTags.Name;
};

/*
 * component is a string, byte array, ArrayBuffer, Uint8Array or Name.
 * Convert to Uint8Array and add to this Name.
 * If a component is a string, encode as utf8.
 * Return this Name object to allow chaining calls to add.
 */
Name.prototype.add = function(component){
    var result;
    if(typeof component == 'string')
        result = DataUtils.stringToUtf8Array(component);
	else if(typeof component == 'object' && component instanceof Uint8Array)
        result = new Uint8Array(component);
	else if(typeof component == 'object' && component instanceof ArrayBuffer) {
        // Make a copy.  Don't use ArrayBuffer.slice since it isn't always supported.
        result = new Uint8Array(new ArrayBuffer(component.byteLength));
        result.set(new Uint8Array(component));
    }
    else if (typeof component == 'object' && component instanceof Name) {
        var components;
        if (component == this)
            // special case, when we need to create a copy
            components = this.components.slice(0, this.components.length);
        else
            components = component.components;
        
        for (var i = 0; i < components.length; ++i)
            this.components.push(new Uint8Array(components[i]));
        return this;
    }
	else if(typeof component == 'object')
        // Assume component is a byte array.  We can't check instanceof Array because
        //   this doesn't work in JavaScript if the array comes from a different module.
        result = new Uint8Array(component);
	else 
		throw new Error("Cannot add Name element at index " + this.components.length + 
            ": Invalid type");
    
    this.components.push(result);
	return this;
};

// Return the escaped name string according to "CCNx URI Scheme".
Name.prototype.to_uri = function() {	
    if (this.components.length == 0)
        return "/";
    
	var result = "";
	
	for(var i = 0; i < this.components.length; ++i)
		result += "/"+ Name.toEscapedString(this.components[i]);
	
	return result;	
};

/**
* @brief Add component that represents a segment number
*
* @param number Segment number (integer is expected)
*
* This component has a special format handling:
* - if number is zero, then %00 is added
* - if number is between 1 and 255, %00%01 .. %00%FF is added
* - ...
*/
Name.prototype.addSegment = function(number) {
    var segmentNumberBigEndian = DataUtils.nonNegativeIntToBigEndian(number);
    // Put a 0 byte in front.
    var segmentNumberComponent = new Uint8Array(segmentNumberBigEndian.length + 1);
    segmentNumberComponent.set(segmentNumberBigEndian, 1);

    this.components.push(segmentNumberComponent);
    return this;
};

/*
 * Return a new Name with the first nComponents components of this Name.
 */
Name.prototype.getPrefix = function(nComponents) {
    return new Name(this.components.slice(0, nComponents));
}

/*
 * Return a new ArrayBuffer of the component at i.
 */
Name.prototype.getComponent = function(i) {
    var result = new ArrayBuffer(this.components[i].length);
    new Uint8Array(result).set(this.components[i]);
    return result;
}

/*
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

/*
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

/*
 * Find the last component in name that has a ContentDigest and return the digest value as Uint8Array, 
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

/*
 * If component is a ContentDigest, return the digest value as a Uint8Array subarray (don't modify!).
 * If not a ContentDigest, return null.
 * A ContentDigest component is Name.ContentDigestPrefix + 32 bytes + Name.ContentDigestSuffix.
 */
Name.getComponentContentDigestValue = function(component) {
    var digestComponentLength = Name.ContentDigestPrefix.length + 32 + Name.ContentDigestSuffix.length; 
    // Check for the correct length and equal ContentDigestPrefix and ContentDigestSuffix.
    if (component.length == digestComponentLength &&
        DataUtils.arraysEqual(component.subarray(0, Name.ContentDigestPrefix.length), 
                              Name.ContentDigestPrefix) &&
        DataUtils.arraysEqual(component.subarray
           (component.length - Name.ContentDigestSuffix.length, component.length),
                              Name.ContentDigestSuffix))
       return component.subarray(Name.ContentDigestPrefix.length, Name.ContentDigestPrefix.length + 32);
   else
       return null;
}

// Meta GUID "%C1.M.G%C1" + ContentDigest with a 32 byte BLOB. 
Name.ContentDigestPrefix = new Uint8Array([0xc1, 0x2e, 0x4d, 0x2e, 0x47, 0xc1, 0x01, 0xaa, 0x02, 0x85]);
Name.ContentDigestSuffix = new Uint8Array([0x00]);

/*
 * Return component as an escaped string according to "CCNx URI Scheme".
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
            var value = component[i];
            // Check for 0-9, A-Z, a-z, (+), (-), (.), (_)
            if (value >= 0x30 && value <= 0x39 || value >= 0x41 && value <= 0x5a ||
                value >= 0x61 && value <= 0x7a || value == 0x2b || value == 0x2d || 
                value == 0x2e || value == 0x5f)
                result += String.fromCharCode(value);
            else
                result += "%" + (value < 16 ? "0" : "") + value.toString(16).toUpperCase();
        }
    }
    return result;
};

/*
 * Return component as a Uint8Array by decoding the escapedString according to "CCNx URI Scheme".
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

Name.prototype.match = function(/*Name*/ name) {
	var i_name = this.components;
	var o_name = name.components;

	// The intrest name is longer than the name we are checking it against.
	if (i_name.length > o_name.length)
            return false;

	// Check if at least one of given components doesn't match.
    for (var i = 0; i < i_name.length; ++i) {
        if (!DataUtils.arraysEqual(i_name[i], o_name[i]))
            return false;
    }

	return true;
};

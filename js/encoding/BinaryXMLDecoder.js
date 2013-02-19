/**
 * This class is used to decode ccnb binary elements (blob, type/value pairs).
 * 
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 */

var XML_EXT = 0x00; 
	
var XML_TAG = 0x01; 
	
var XML_DTAG = 0x02; 
	
var XML_ATTR = 0x03; 
 
var XML_DATTR = 0x04; 
	
var XML_BLOB = 0x05; 
	
var XML_UDATA = 0x06; 
	
var XML_CLOSE = 0x0;

var XML_SUBTYPE_PROCESSING_INSTRUCTIONS = 16; 
	

var XML_TT_BITS = 3;
var XML_TT_MASK = ((1 << XML_TT_BITS) - 1);
var XML_TT_VAL_BITS = XML_TT_BITS + 1;
var XML_TT_VAL_MASK = ((1 << (XML_TT_VAL_BITS)) - 1);
var XML_REG_VAL_BITS = 7;
var XML_REG_VAL_MASK = ((1 << XML_REG_VAL_BITS) - 1);
var XML_TT_NO_MORE = (1 << XML_REG_VAL_BITS); // 0x80
var BYTE_MASK = 0xFF;
var LONG_BYTES = 8;
var LONG_BITS = 64;
	
var bits_11 = 0x0000007FF;
var bits_18 = 0x00003FFFF;
var bits_32 = 0x0FFFFFFFF;



//returns a string
tagToString = function(/*long*/ tagVal) {
	if ((tagVal >= 0) && (tagVal < CCNProtocolDTagsStrings.length)) {
		return CCNProtocolDTagsStrings[tagVal];
	} else if (tagVal == CCNProtocolDTags.CCNProtocolDataUnit) {
		return CCNProtocolDTags.CCNPROTOCOL_DATA_UNIT;
	}
	return null;
};

//returns a Long
stringToTag =  function(/*String*/ tagName) {
	// the slow way, but right now we don't care.... want a static lookup for the forward direction
	for (var i=0; i < CCNProtocolDTagsStrings.length; ++i) {
		if ((null != CCNProtocolDTagsStrings[i]) && (CCNProtocolDTagsStrings[i] == tagName)) {
			return i;
		}
	}
	if (CCNProtocolDTags.CCNPROTOCOL_DATA_UNIT == tagName) {
		return CCNProtocolDTags.CCNProtocolDataUnit;
	}
	return null;
};

//console.log(stringToTag(64));
var BinaryXMLDecoder = function BinaryXMLDecoder(istream){
	var MARK_LEN=512;
	var DEBUG_MAX_LEN =  32768;
	
	this.istream = istream;
	this.offset = 0;
};

BinaryXMLDecoder.prototype.initializeDecoding = function() {
		//if (!this.istream.markSupported()) {
			//throw new IllegalArgumentException(this.getClass().getName() + ": input stream must support marking!");
		//}
}

BinaryXMLDecoder.prototype.readStartDocument = function(){
		// Currently no start document in binary encoding.
	}

BinaryXMLDecoder.prototype.readEndDocument = function() {
		// Currently no end document in binary encoding.
	};

BinaryXMLDecoder.prototype.readStartElement = function(
		//String 
		startTag,
		//TreeMap<String, String> 
		attributes) {
	
		
		//NOT SURE
		//if(typeof startTag == 'number')
			//startTag = tagToString(startTag);
		
			//TypeAndVal 
			var tv = this.decodeTypeAndVal();
			
			if (null == tv) {
				throw new ContentDecodingException(new Error("Expected start element: " + startTag + " got something not a tag."));
			}
			
			//String 
			var decodedTag = null;
			//console.log(tv);
			//console.log(typeof tv);
			
			//console.log(XML_TAG);
			if (tv.type() == XML_TAG) {
				//console.log('got here');
				//Log.info(Log.FAC_ENCODING, "Unexpected: got tag in readStartElement; looking for tag " + startTag + " got length: " + (int)tv.val()+1);
				// Tag value represents length-1 as tags can never be empty.
				var valval ;
				if(typeof tv.val() == 'string'){
					valval = (parseInt(tv.val())) + 1;
				}
				else
					valval = (tv.val())+ 1;
				
				//console.log('valval is ' +valval);
				
				decodedTag = this.decodeUString(valval);
				
			} else if (tv.type() == XML_DTAG) {
				//console.log('gothere');
				//console.log(tv.val());
				//decodedTag = tagToString(tv.val());
				//console.log()
				decodedTag = tv.val();
			}
			
			//console.log(decodedTag);
			//console.log('startTag is '+startTag);
			
			
			if ((null ==  decodedTag) || decodedTag != startTag ) {
				console.log('expecting '+ startTag + ' but got '+ decodedTag);
				throw new ContentDecodingException(new Error("Expected start element: " + startTag + " got: " + decodedTag + "(" + tv.val() + ")"));
			}
			
			// DKS: does not read attributes out of stream if caller doesn't
			// ask for them. Should possibly peek and skip over them regardless.
			// TODO: fix this
			if (null != attributes) {
				readAttributes(attributes); 
			}
	}
	

BinaryXMLDecoder.prototype.readAttributes = function(
	// array of [attributeName, attributeValue] 
	attributes) {
	
	if (null == attributes) {
		return;
	}

	try {
		// Now need to get attributes.
		//TypeAndVal 
		var nextTV = this.peekTypeAndVal();

		while ((null != nextTV) && ((XML_ATTR == nextTV.type()) ||
				(XML_DATTR == nextTV.type()))) {

			// Decode this attribute. First, really read the type and value.
			//this.TypeAndVal 
			var thisTV = this.decodeTypeAndVal();

			//String 
			var attributeName = null;
			if (XML_ATTR == thisTV.type()) {
				// Tag value represents length-1 as attribute names cannot be empty.
				var valval ;
				if(typeof thisTV.val() == 'string'){
					valval = (parseInt(thisTV.val())) + 1;
				}
				else
					valval = (thisTV.val())+ 1;
				
				attributeName = this.decodeUString(valval);

			} else if (XML_DATTR == thisTV.type()) {
				// DKS TODO are attributes same or different dictionary?
				attributeName = tagToString(thisTV.val());
				if (null == attributeName) {
					throw new ContentDecodingException(new Error("Unknown DATTR value" + thisTV.val()));
				}
			}
			// Attribute values are always UDATA
			//String
			var attributeValue = this.decodeUString();

			//
			attributes.push([attributeName, attributeValue]);

			nextTV = this.peekTypeAndVal();
		}
	} catch ( e) {
		throw new ContentDecodingException(new Error("readStartElement", e));
	}
};

//returns a string
BinaryXMLDecoder.prototype.peekStartElementAsString = function() {
	//this.istream.mark(MARK_LEN);

	//String 
	var decodedTag = null;
	var previousOffset = this.offset;
	try {
		// Have to distinguish genuine errors from wrong tags. Could either use
		// a special exception subtype, or redo the work here.
		//this.TypeAndVal 
		var tv = this.decodeTypeAndVal();

		if (null != tv) {

			if (tv.type() == XML_TAG) {
				/*if (tv.val()+1 > DEBUG_MAX_LEN) {
					throw new ContentDecodingException(new Error("Decoding error: length " + tv.val()+1 + " longer than expected maximum length!")(;
				}*/

				// Tag value represents length-1 as tags can never be empty.
				var valval ;
				if(typeof tv.val() == 'string'){
					valval = (parseInt(tv.val())) + 1;
				}
				else
					valval = (tv.val())+ 1;
				
				decodedTag = this.decodeUString(valval);
				
				//Log.info(Log.FAC_ENCODING, "Unexpected: got text tag in peekStartElement; length: " + valval + " decoded tag = " + decodedTag);

			} else if (tv.type() == XML_DTAG) {
				decodedTag = tagToString(tv.val());					
			}

		} // else, not a type and val, probably an end element. rewind and return false.

	} catch ( e) {

	} finally {
		try {
			this.offset = previousOffset;
		} catch ( e) {
			Log.logStackTrace(Log.FAC_ENCODING, Level.WARNING, e);
			throw new ContentDecodingException(new Error("Cannot reset stream! " + e.getMessage(), e));
		}
	}
	return decodedTag;
};

BinaryXMLDecoder.prototype.peekStartElement = function(
		//String 
		startTag) {
	//String 
	if(typeof startTag == 'string'){
		var decodedTag = this.peekStartElementAsString();
		
		if ((null !=  decodedTag) && decodedTag == startTag) {
			return true;
		}
		return false;
	}
	else if(typeof startTag == 'number'){
		var decodedTag = this.peekStartElementAsLong();
		if ((null !=  decodedTag) && decodedTag == startTag) {
			return true;
		}
		return false;
	}
	else{
		throw new ContentDecodingException(new Error("SHOULD BE STRING OR NUMBER"));
	}
}
//returns Long
BinaryXMLDecoder.prototype.peekStartElementAsLong = function() {
		//this.istream.mark(MARK_LEN);

		//Long
		var decodedTag = null;
		
		var previousOffset = this.offset;
		
		try {
			// Have to distinguish genuine errors from wrong tags. Could either use
			// a special exception subtype, or redo the work here.
			//this.TypeAndVal
			var tv = this.decodeTypeAndVal();

			if (null != tv) {

				if (tv.type() == XML_TAG) {
					if (tv.val()+1 > DEBUG_MAX_LEN) {
						throw new ContentDecodingException(new Error("Decoding error: length " + tv.val()+1 + " longer than expected maximum length!"));
					}

					var valval ;
					if(typeof tv.val() == 'string'){
						valval = (parseInt(tv.val())) + 1;
					}
					else
						valval = (tv.val())+ 1;
					
					// Tag value represents length-1 as tags can never be empty.
					//String 
					var strTag = this.decodeUString(valval);
					
					decodedTag = stringToTag(strTag);
					
					//Log.info(Log.FAC_ENCODING, "Unexpected: got text tag in peekStartElement; length: " + valval + " decoded tag = " + decodedTag);
					
				} else if (tv.type() == XML_DTAG) {
					decodedTag = tv.val();					
				}

			} // else, not a type and val, probably an end element. rewind and return false.

		} catch ( e) {
			
		} finally {
			try {
				//this.istream.reset();
				this.offset = previousOffset;
			} catch ( e) {
				Log.logStackTrace(Log.FAC_ENCODING, Level.WARNING, e);
				throw new Error("Cannot reset stream! " + e.getMessage(), e);
			}
		}
		return decodedTag;
	};


// returns a byte[]
BinaryXMLDecoder.prototype.readBinaryElement = function(
		//long 
		startTag,
		//TreeMap<String, String> 
		attributes){
	//byte [] 
	var blob = null;
	
	this.readStartElement(startTag, attributes);
	blob = this.readBlob();	

	return blob;
};
	
	
BinaryXMLDecoder.prototype.readEndElement = function(){
			if(LOG>4)console.log('this.offset is '+this.offset);
			
			var next = this.istream[this.offset]; 
			
			this.offset++;
			//read();
			
			if(LOG>4)console.log('XML_CLOSE IS '+XML_CLOSE);
			if(LOG>4)console.log('next is '+next);
			
			if (next != XML_CLOSE) {
				console.log("Expected end element, got: " + next);
				throw new ContentDecodingException(new Error("Expected end element, got: " + next));
			}
	};


//String	
BinaryXMLDecoder.prototype.readUString = function(){
			//String 
			var ustring = this.decodeUString();	
			this.readEndElement();
			return ustring;

	};
	

//returns a uint8array
BinaryXMLDecoder.prototype.readBlob = function() {
			//uint8array
			
			var blob = this.decodeBlob();	
			this.readEndElement();
			return blob;

	};


//CCNTime
BinaryXMLDecoder.prototype.readDateTime = function(
	//long 
	startTag)  {
	//byte [] 
	
	var byteTimestamp = this.readBinaryElement(startTag);

	//var lontimestamp = DataUtils.byteArrayToUnsignedLong(byteTimestamp);

	byteTimestamp = DataUtils.toHex(byteTimestamp);
	
	
	byteTimestamp = parseInt(byteTimestamp, 16);

	var lontimestamp = (byteTimestamp/ 4096) * 1000;

	//if(lontimestamp<0) lontimestamp =  - lontimestamp;

	if(LOG>3) console.log('DECODED DATE WITH VALUE');
	if(LOG>3) console.log(lontimestamp);
	

	//CCNTime 
	var timestamp = new CCNTime(lontimestamp);
	//timestamp.setDateBinary(byteTimestamp);
	
	if (null == timestamp) {
		throw new ContentDecodingException(new Error("Cannot parse timestamp: " + DataUtils.printHexBytes(byteTimestamp)));
	}		
	return timestamp;
};

BinaryXMLDecoder.prototype.decodeTypeAndVal = function() {
	
	/*int*/var type = -1;
	/*long*/var val = 0;
	/*boolean*/var more = true;

	do {
		
		var next = this.istream[this.offset ];
		
		
		if (next < 0) {
			return null; 
		}

		if ((0 == next) && (0 == val)) {
			return null;
		}
		
		more = (0 == (next & XML_TT_NO_MORE));
		
		if  (more) {
			val = val << XML_REG_VAL_BITS;
			val |= (next & XML_REG_VAL_MASK);
		} else {

			type = next & XML_TT_MASK;
			val = val << XML_TT_VAL_BITS;
			val |= ((next >>> XML_TT_BITS) & XML_TT_VAL_MASK);
		}
		
		this.offset++;
		
	} while (more);
	
	if(LOG>3)console.log('TYPE is '+ type + ' VAL is '+ val);

	return new TypeAndVal(type, val);
};



//TypeAndVal
BinaryXMLDecoder.peekTypeAndVal = function() {
	//TypeAndVal 
	var tv = null;
	
	//this.istream.mark(LONG_BYTES*2);		
	
	var previousOffset = this.offset;
	
	try {
		tv = this.decodeTypeAndVal();
	} finally {
		//this.istream.reset();
		this.offset = previousOffset;
	}
	
	return tv;
};


//Uint8Array
BinaryXMLDecoder.prototype.decodeBlob = function(
		//int 
		blobLength) {
	
	if(null == blobLength){
		//TypeAndVal
		var tv = this.decodeTypeAndVal();

		var valval ;
		
		if(typeof tv.val() == 'string'){
			valval = (parseInt(tv.val()));
		}
		else
			valval = (tv.val());
		
		//console.log('valval here is ' + valval);
		return  this.decodeBlob(valval);
	}
	
	//
	//Uint8Array
	var bytes = this.istream.subarray(this.offset, this.offset+ blobLength);
	this.offset += blobLength;
	
	return bytes;
};

//String
BinaryXMLDecoder.prototype.decodeUString = function(
		//int 
		byteLength) {
	if(null == byteLength ){
		var tempStreamPosition = this.offset;
			
		//TypeAndVal 
		var tv = this.decodeTypeAndVal();
		
		if(LOG>3)console.log('TV is '+tv);
		if(LOG>3)console.log(tv);
		
		if(LOG>3)console.log('Type of TV is '+typeof tv);
	
		if ((null == tv) || (XML_UDATA != tv.type())) { // if we just have closers left, will get back null
			//if (Log.isLoggable(Log.FAC_ENCODING, Level.FINEST))
				//Log.finest(Log.FAC_ENCODING, "Expected UDATA, got " + ((null == tv) ? " not a tag " : tv.type()) + ", assuming elided 0-length blob.");
			
			this.offset = tempStreamPosition;
			
			return "";
		}
			
		return this.decodeUString(tv.val());
	}
	else{
		//uint8array 
		var stringBytes = this.decodeBlob(byteLength);
		
		//return DataUtils.getUTF8StringFromBytes(stringBytes);
		return  DataUtils.toString(stringBytes);
		
	}
};

//OBject containg a pair of type and value
var TypeAndVal = function TypeAndVal(_type,_val) {
	this.t = _type;
	this.v = _val;
};

TypeAndVal.prototype.type = function(){
	return this.t;
};

TypeAndVal.prototype.val = function(){
	return this.v;
};




BinaryXMLDecoder.prototype.readIntegerElement =function(
	//String 
	startTag) {

	//String 
	if(LOG>4) console.log('READING INTEGER '+ startTag);
	if(LOG>4) console.log('TYPE OF '+ typeof startTag);
	
	var strVal = this.readUTF8Element(startTag);
	
	return parseInt(strVal);
};


BinaryXMLDecoder.prototype.readUTF8Element =function(
			//String 
			startTag,
			//TreeMap<String, String> 
			attributes) {
			//throws Error where name == "ContentDecodingException" 

		this.readStartElement(startTag, attributes); // can't use getElementText, can't get attributes
		//String 
		var strElementText = this.readUString();
		return strElementText;
};


/* 
 * Set the offset into the input, used for the next read.
 */
BinaryXMLDecoder.prototype.seek = function(
        //int
        offset) {
    this.offset = offset;
}

/*
 * Call with: throw new ContentDecodingException(new Error("message")).
 */
function ContentDecodingException(error) {
    this.message = error.message;
    // Copy lineNumber, etc. from where new Error was called.
    for (var prop in error)
        this[prop] = error[prop];
}
ContentDecodingException.prototype = new Error();
ContentDecodingException.prototype.name = "ContentDecodingException";


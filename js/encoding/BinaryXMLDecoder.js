/*
 * This class is used to encode and decode binary elements ( blog, type/value pairs)
 * 
 * @author: ucla-cs
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
	//console.log('istream is '+ this.istream);
	this.offset = 0;
};


BinaryXMLDecoder.prototype.readStartElement =function(
	//String
	startTag,				    
	//TreeMap<String, String>
	attributes) {

	try {
		//this.TypeAndVal 
		tv = this.decodeTypeAndVal(this.istream);

		if (null == tv) {
			throw new Exception("Expected start element: " + startTag + " got something not a tag.");
		}
		
		//String 
		decodedTag = null;
		
		if (tv.type() == XML_TAG) {
			
			decodedTag = this.decodeUString(this.Istream, tv.val()+1);
			
		} else if (tv.type() == XML_DTAG) {
			decodedTag = tagToString(tv.val());	
		}
		
		if ((null ==  decodedTag) || decodedTag != startTag) {
			throw new Exception("Expected start element: " + startTag + " got: " + decodedTag + "(" + tv.val() + ")");
		}
		
		if (null != attributes) {
			readAttributes(attributes); 
		}
		
	} catch (e) {
		throw new Exception("readStartElement", e);
	}
};

BinaryXMLDecoder.prototype.readAttributes = function(
	//TreeMap<String,String> 
	attributes){
	
	if (null == attributes) {
		return;
	}

	try {

		//this.TypeAndVal 
		nextTV = this.peekTypeAndVal(this.istream);

		while ((null != nextTV) && ((XML_ATTR == nextTV.type()) ||
				(XML_DATTR == nextTV.type()))) {

			//this.TypeAndVal 
			thisTV = this.decodeTypeAndVal(this.Istream);

			var attributeName = null;
			if (XML_ATTR == thisTV.type()) {
				
				attributeName = this.decodeUString(this.istream, thisTV.val()+1);

			} else if (XML_DATTR == thisTV.type()) {
				// DKS TODO are attributes same or different dictionary?
				attributeName = tagToString(thisTV.val());
				if (null == attributeName) {
					throw new ContentDecodingException("Unknown DATTR value" + thisTV.val());
				}
			}
			
			var attributeValue = this.decodeUString(this.istream);

			attributes.put(attributeName, attributeValue);

			nextTV = this.peekTypeAndVal(this.istream);
		}

	} catch ( e) {

		throw new ContentDecodingException("readStartElement", e);
	}
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
		
		//try {
			//TypeAndVal 
			tv = this.decodeTypeAndVal(this.istream);
			
			if (null == tv) {
				throw new Exception("Expected start element: " + startTag + " got something not a tag.");
			}
			
			//String 
			decodedTag = null;
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
				
				decodedTag = this.decodeUString(this.istream,  valval);
				
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
				console.log('expecting '+ startag + ' but got '+ decodedTag);
				throw new Exception("Expected start element: " + startTag + " got: " + decodedTag + "(" + tv.val() + ")");
			}
			
			// DKS: does not read attributes out of stream if caller doesn't
			// ask for them. Should possibly peek and skip over them regardless.
			// TODO: fix this
			if (null != attributes) {
				readAttributes(attributes); 
			}
			
		//} catch ( e) {
			//console.log(e);
			//throw new Exception("readStartElement", e);
		//}
	}
	

BinaryXMLDecoder.prototype.readAttributes = function(
	//TreeMap<String,String> 
	attributes) {
	
	if (null == attributes) {
		return;
	}

	try {
		// Now need to get attributes.
		//TypeAndVal 
		nextTV = this.peekTypeAndVal(this.istream);

		while ((null != nextTV) && ((XML_ATTR == nextTV.type()) ||
				(XML_DATTR == nextTV.type()))) {

			// Decode this attribute. First, really read the type and value.
			//this.TypeAndVal 
			thisTV = this.decodeTypeAndVal(this.istream);

			//String 
			attributeName = null;
			if (XML_ATTR == thisTV.type()) {
				// Tag value represents length-1 as attribute names cannot be empty.
				var valval ;
				if(typeof tv.val() == 'string'){
					valval = (parseInt(tv.val())) + 1;
				}
				else
					valval = (tv.val())+ 1;
				
				attributeName = this.decodeUString(this.istream,valval);

			} else if (XML_DATTR == thisTV.type()) {
				// DKS TODO are attributes same or different dictionary?
				attributeName = tagToString(thisTV.val());
				if (null == attributeName) {
					throw new Exception("Unknown DATTR value" + thisTV.val());
				}
			}
			// Attribute values are always UDATA
			//String
			attributeValue = this.decodeUString(this.istream);

			//
			attributes.push([attributeName, attributeValue]);

			nextTV = this.peekTypeAndVal(this.istream);
		}

	} catch ( e) {
		Log.logStackTrace(Log.FAC_ENCODING, Level.WARNING, e);
		throw new Exception("readStartElement", e);
	}
};

//returns a string
BinaryXMLDecoder.prototype.peekStartElementAsString = function() {
	//this.istream.mark(MARK_LEN);

	//String 
	decodedTag = null;
	var previousOffset = this.offset;
	try {
		// Have to distinguish genuine errors from wrong tags. Could either use
		// a special exception subtype, or redo the work here.
		//this.TypeAndVal 
		tv = this.decodeTypeAndVal(this.istream);

		if (null != tv) {

			if (tv.type() == XML_TAG) {
				/*if (tv.val()+1 > DEBUG_MAX_LEN) {
					throw new ContentDecodingException("Decoding error: length " + tv.val()+1 + " longer than expected maximum length!");
				}*/

				// Tag value represents length-1 as tags can never be empty.
				var valval ;
				if(typeof tv.val() == 'string'){
					valval = (parseInt(tv.val())) + 1;
				}
				else
					valval = (tv.val())+ 1;
				
				decodedTag = this.decodeUString(this.istream, valval);
				
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
			throw new ContentDecodingException("Cannot reset stream! " + e.getMessage(), e);
		}
	}
	return decodedTag;
};

BinaryXMLDecoder.prototype.peekStartElement = function(
		//String 
		startTag) {
	//String 
	if(typeof startTag == 'string'){
		decodedTag = this.peekStartElementAsString();
		
		if ((null !=  decodedTag) && decodedTag == startTag) {
			return true;
		}
		return false;
	}
	else if(typeof startTag == 'number'){
		decodedTag = this.peekStartElementAsLong();
		if ((null !=  decodedTag) && decodedTag == startTag) {
			return true;
		}
		return false;
	}
	else{
		throw new Exception("SHOULD BE STRING OR NUMBER");
	}
}
//returns Long
BinaryXMLDecoder.prototype.peekStartElementAsLong = function() {
		//this.istream.mark(MARK_LEN);

		//Long
		decodedTag = null;
		
		var previousOffset = this.offset;
		
		try {
			// Have to distinguish genuine errors from wrong tags. Could either use
			// a special exception subtype, or redo the work here.
			//this.TypeAndVal
			tv = this.decodeTypeAndVal(this.istream);

			if (null != tv) {

				if (tv.type() == XML_TAG) {
					if (tv.val()+1 > DEBUG_MAX_LEN) {
						throw new ContentDecodingException("Decoding error: length " + tv.val()+1 + " longer than expected maximum length!");
					}

					var valval ;
					if(typeof tv.val() == 'string'){
						valval = (parseInt(tv.val())) + 1;
					}
					else
						valval = (tv.val())+ 1;
					
					// Tag value represents length-1 as tags can never be empty.
					//String 
					strTag = this.decodeUString(this.istream, valval);
					
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
				throw new Exception("Cannot reset stream! " + e.getMessage(), e);
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
	blob = null;
	
		this.readStartElement(startTag, attributes);
		blob = this.readBlob();
	

	return blob;

};
	
	
BinaryXMLDecoder.prototype.readEndElement = function(){
		//try {
			if(LOG>4)console.log('this.offset is '+this.offset);
			
			var next = this.istream[this.offset]; 
			
			this.offset++;
			//read();
			
			if(LOG>4)console.log('XML_CLOSE IS '+XML_CLOSE);
			if(LOG>4)console.log('next is '+next);
			
			if (next != XML_CLOSE) {
				console.log("Expected end element, got: " + next);
				throw new ContentDecodingException("Expected end element, got: " + next);
			}
		//} catch ( e) {
			//throw new ContentDecodingException(e);
		//}
	};


//String	
BinaryXMLDecoder.prototype.readUString = function(){
			//String 
			ustring = this.decodeUString(this.istream);	
			this.readEndElement();
			return ustring;

	};
	

//returns a byte[]
BinaryXMLDecoder.prototype.readBlob = function() {
			//byte []
			
			blob = this.decodeBlob(this.istream);	
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

	var byteTimestamp = DataUtils.toHex(byteTimestamp);
	
	
	var byteTimestamp = parseInt(byteTimestamp, 16);

	lontimestamp = (byteTimestamp/ 4096) * 1000;

	//if(lontimestamp<0) lontimestamp =  - lontimestamp;

	if(LOG>3) console.log('DECODED DATE WITH VALUE');
	if(LOG>3) console.log(lontimestamp);
	

	//CCNTime 
	timestamp = new CCNTime(lontimestamp);
	//timestamp.setDateBinary(byteTimestamp);
	
	if (null == timestamp) {
		throw new ContentDecodingException("Cannot parse timestamp: " + DataUtils.printHexBytes(byteTimestamp));
	}		
	return timestamp;
};

BinaryXMLDecoder.prototype.decodeTypeAndVal = function(
		/*InputStream*/
		istream) {
	
	/*int*/next;
	/*int*/type = -1;
	/*long*/val = 0;
	/*boolean*/more = true;

	
	//var savedOffset = this.offset;
	var count = 0;
	
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
BinaryXMLDecoder.peekTypeAndVal = function(
		//InputStream 
		istream) {
	//TypeAndVal 
	tv = null;
	
	//istream.mark(LONG_BYTES*2);		
	
	var previousOffset = this.offset;
	
	try {
		tv = this.decodeTypeAndVal(this.istream);
	} finally {
		//istream.reset();
		this.offset = previousOffset;
	}
	
	return tv;
};


//byte[]
BinaryXMLDecoder.prototype.decodeBlob = function(
		//InputStream 
		istream, 
		//int 
		blobLength) {
	
	
	if(null == blobLength){
		//TypeAndVal
		tv = this.decodeTypeAndVal(this.istream);

		var valval ;
		
		if(typeof tv.val() == 'string'){
			valval = (parseInt(tv.val()));
		}
		else
			valval = (tv.val());
		
		//console.log('valval here is ' + valval);
		return  this.decodeBlob(this.istream, valval);
	}
	
	//
	//byte [] 

	bytes = this.istream.slice(this.offset, this.offset+ blobLength);
	this.offset += blobLength;
	
	//int 
	return bytes;
	
	count = 0;

};

var count =0;

//String
BinaryXMLDecoder.prototype.decodeUString = function(
		//InputStream 
		istream, 
		//int 
		byteLength) {
	
	/*
	console.log('COUNT IS '+count);
	console.log('INPUT BYTELENGTH IS '+byteLength);
	count++;
	if(null == byteLength||  undefined == byteLength){
		console.log("!!!!");
		tv = this.decodeTypeAndVal(this.istream);
		var valval ;
		if(typeof tv.val() == 'string'){
			valval = (parseInt(tv.val()));
		}
		else
			valval = (tv.val());
		
		if(LOG>4) console.log('valval  is ' + valval);
		byteLength= this.decodeUString(this.istream, valval);
		
		//if(LOG>4) console.log('byte Length found in type val is '+ byteLength.charCodeAt(0));
		byteLength = parseInt(byteLength);
		
		
		//byteLength = byteLength.charCodeAt(0);
		//if(LOG>4) console.log('byte Length found in type val is '+ byteLength);
	}
	if(LOG>4)console.log('byteLength is '+byteLength);
	if(LOG>4)console.log('type of byteLength is '+typeof byteLength);
	
	stringBytes = this.decodeBlob(this.istream, byteLength);
	
	//console.log('String bytes are '+ stringBytes);
	//console.log('stringBytes);
	
	if(LOG>4)console.log('byteLength is '+byteLength);
	if(LOG>4)console.log('this.offset is '+this.offset);

	tempBuffer = this.istream.slice(this.offset, this.offset+byteLength);
	if(LOG>4)console.log('TEMPBUFFER IS' + tempBuffer);
	if(LOG>4)console.log( tempBuffer);

	if(LOG>4)console.log('ADDING to offset value' + byteLength);
	this.offset+= byteLength;
	//if(LOG>3)console.log('read the String' + tempBuffer.toString('ascii'));
	//return tempBuffer.toString('ascii');//
	
	
	//if(LOG>3)console.log( 'STRING READ IS '+ DataUtils.getUTF8StringFromBytes(stringBytes) ) ;
	//if(LOG>3)console.log( 'STRING READ IS '+ DataUtils.getUTF8StringFromBytes(tempBuffer) ) ;
	//if(LOG>3)console.log(DataUtils.getUTF8StringFromBytes(tempBuffer) ) ;
	//return DataUtils.getUTF8StringFromBytes(tempBuffer);
	
	if(LOG>3)console.log( 'STRING READ IS '+ DataUtils.toString(stringBytes) ) ;
	if(LOG>3)console.log( 'TYPE OF STRING READ IS '+ typeof DataUtils.toString(stringBytes) ) ;

	return  DataUtils.toString(stringBytes);*/

	if(null == byteLength ){
		var tempStreamPosition = this.offset;
			
		//TypeAndVal 
		tv = this.decodeTypeAndVal(istream);
		
		if(LOG>3)console.log('TV is '+tv);
		if(LOG>3)console.log(tv);
		
		if(LOG>3)console.log('Type of TV is '+typeof tv);
	
		if ((null == tv) || (XML_UDATA != tv.type())) { // if we just have closers left, will get back null
			//if (Log.isLoggable(Log.FAC_ENCODING, Level.FINEST))
				//Log.finest(Log.FAC_ENCODING, "Expected UDATA, got " + ((null == tv) ? " not a tag " : tv.type()) + ", assuming elided 0-length blob.");
			
			this.offset = tempStreamPosition;
			
			return "";
		}
			
		return this.decodeUString(istream, tv.val());
	}
	else{
		//byte [] 
		stringBytes = this.decodeBlob(istream, byteLength);
		
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
//TODO






BinaryXMLDecoder.prototype.readIntegerElement =function(
	//String 
	startTag) {

	//String 
	if(LOG>4) console.log('READING INTEGER '+ startTag);
	if(LOG>4) console.log('TYPE OF '+ typeof startTag);
	
	//try {
		
	strVal = this.readUTF8Element(startTag);

	//}
	//catch (e) {
		//throw new Exception("Cannot parse " + startTag + ": " + strVal);
	//}
	
	return parseInt(strVal);
};


BinaryXMLDecoder.prototype.readUTF8Element =function(
			//String 
			startTag,
			//TreeMap<String, String> 
			attributes) {
			//throws ContentDecodingException 

		this.readStartElement(startTag, attributes); // can't use getElementText, can't get attributes
		//String 
		strElementText = this.readUString();
		return strElementText;
};

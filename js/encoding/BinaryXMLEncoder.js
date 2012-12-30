/**
 * This class is used to encode ccnb binary elements (blob, type/value pairs).
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


var BinaryXMLEncoder = function BinaryXMLEncoder(){
	this.ostream = new DynamicUint8Array(100);
	this.offset =0;
	this.CODEC_NAME = "Binary";
};

/*
 * Encode utf8Content as utf8.
 */
BinaryXMLEncoder.prototype.writeUString = function(/*String*/ utf8Content) {
	this.encodeUString(utf8Content, XML_UDATA);
};


BinaryXMLEncoder.prototype.writeBlob = function(
		/*Uint8Array*/ binaryContent
		) {
	
	if(LOG >3) console.log(binaryContent);
	
	this.encodeBlob(binaryContent, binaryContent.length);
};


BinaryXMLEncoder.prototype.writeStartElement = function(
	/*String*/ tag, 
	/*TreeMap<String,String>*/ attributes
	) {

	/*Long*/ var dictionaryVal = tag; //stringToTag(tag);
	
	if (null == dictionaryVal) {
		this.encodeUString(tag, XML_TAG);
	} else {
		this.encodeTypeAndVal(XML_DTAG, dictionaryVal);
	}
	
	if (null != attributes) {
		this.writeAttributes(attributes); 
	}
};


BinaryXMLEncoder.prototype.writeEndElement = function() {
    this.ostream.ensureLength(this.offset + 1);
	this.ostream.array[this.offset] = XML_CLOSE;
	this.offset += 1;
}


BinaryXMLEncoder.prototype.writeAttributes = function(/*TreeMap<String,String>*/ attributes) {
	if (null == attributes) {
		return;
	}

	// the keySet of a TreeMap is sorted.

	for(var i=0; i<attributes.length;i++){
		var strAttr = attributes[i].k;
		var strValue = attributes[i].v;

		var dictionaryAttr = stringToTag(strAttr);
		if (null == dictionaryAttr) {
			// not in dictionary, encode as attr
			// compressed format wants length of tag represented as length-1
			// to save that extra bit, as tag cannot be 0 length.
			// encodeUString knows to do that.
			this.encodeUString(strAttr, XML_ATTR);
		} else {
			this.encodeTypeAndVal(XML_DATTR, dictionaryAttr);
		}
		// Write value
		this.encodeUString(strValue);
		
	}
}


//returns a string
stringToTag = function(/*long*/ tagVal) {
	if ((tagVal >= 0) && (tagVal < CCNProtocolDTagsStrings.length)) {
		return CCNProtocolDTagsStrings[tagVal];
	} else if (tagVal == CCNProtocolDTags.CCNProtocolDataUnit) {
		return CCNProtocolDTags.CCNPROTOCOL_DATA_UNIT;
	}
	return null;
};

//returns a Long
tagToString =  function(/*String*/ tagName) {
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

/*
 * If Content is a string, then encode as utf8 and write UDATA.
 */
BinaryXMLEncoder.prototype.writeElement = function(
		//long 
		tag, 
		//byte[] 
		Content,
		//TreeMap<String, String> 
		attributes
		) {
	this.writeStartElement(tag, attributes);
	// Will omit if 0-length
	
	if(typeof Content === 'number') {
		if(LOG>4) console.log('GOING TO WRITE THE NUMBER .charCodeAt(0) ' + Content.toString().charCodeAt(0) );
		if(LOG>4) console.log('GOING TO WRITE THE NUMBER ' + Content.toString() );
		if(LOG>4) console.log('type of number is ' + typeof Content.toString() );
		
		this.writeUString(Content.toString());
		//whatever
	}
	else if(typeof Content === 'string'){
		if(LOG>4) console.log('GOING TO WRITE THE STRING  ' + Content );
		if(LOG>4) console.log('type of STRING is ' + typeof Content );
		
		this.writeUString(Content);
	}
	else{
		if(LOG>4) console.log('GOING TO WRITE A BLOB  ' + Content );

		this.writeBlob(Content);
	}
	
	this.writeEndElement();
}



var TypeAndVal = function TypeAndVal(_type,_val) {
	this.type = _type;
	this.val = _val;
	
};


BinaryXMLEncoder.prototype.encodeTypeAndVal = function(
		//int
		type, 
		//long 
		val
		) {
	
	if(LOG>4) console.log('Encoding type '+ type+ ' and value '+ val);
	
	if(LOG>4) console.log('OFFSET IS ' + this.offset);
	
	if ((type > XML_UDATA) || (type < 0) || (val < 0)) {
		throw new Error("Tag and value must be positive, and tag valid.");
	}
	
	// Encode backwards. Calculate how many bytes we need:
	var numEncodingBytes = this.numEncodingBytes(val);
	this.ostream.ensureLength(this.offset + numEncodingBytes);

	// Bottom 4 bits of val go in last byte with tag.
	this.ostream.array[this.offset + numEncodingBytes - 1] = 
		//(byte)
			(BYTE_MASK &
					(((XML_TT_MASK & type) | 
					 ((XML_TT_VAL_MASK & val) << XML_TT_BITS))) |
					 XML_TT_NO_MORE); // set top bit for last byte
	val = val >>> XML_TT_VAL_BITS;
	
	// Rest of val goes into preceding bytes, 7 bits per byte, top bit
	// is "more" flag.
	var i = this.offset + numEncodingBytes - 2;
	while ((0 != val) && (i >= this.offset)) {
		this.ostream.array[i] = //(byte)
				(BYTE_MASK & (val & XML_REG_VAL_MASK)); // leave top bit unset
		val = val >>> XML_REG_VAL_BITS;
		--i;
	}
	if (val != 0) {
		throw new Error( "This should not happen: miscalculated encoding");
		//Log.warning(Log.FAC_ENCODING, "This should not happen: miscalculated encoding length, have " + val + " left.");
	}
	this.offset+= numEncodingBytes;
	
	return numEncodingBytes;
};

/*
 * Encode ustring as utf8.
 */
BinaryXMLEncoder.prototype.encodeUString = function(
		//String 
		ustring, 
		//byte 
		type) {
	
	if (null == ustring)
		return;
	if (type == XML_TAG || type == XML_ATTR && ustring.length == 0)
		return;
	
	if(LOG>3) console.log("The string to write is ");
	if(LOG>3) console.log(ustring);

	var strBytes = DataUtils.stringToUtf8Array(ustring);
	
	this.encodeTypeAndVal(type, 
						(((type == XML_TAG) || (type == XML_ATTR)) ?
								(strBytes.length-1) :
								strBytes.length));
	
	if(LOG>3) console.log("THE string to write is ");
	
	if(LOG>3) console.log(strBytes);
	
	this.writeString(strBytes);
	this.offset+= strBytes.length;
};



BinaryXMLEncoder.prototype.encodeBlob = function(
		//Uint8Array 
		blob, 
		//int 
		length) {


	if (null == blob)
		return;
	
	if(LOG>4) console.log('LENGTH OF XML_BLOB IS '+length);
	
	/*blobCopy = new Array(blob.Length);
	
	for (i = 0; i < blob.length; i++) //in InStr.ToCharArray())
	{
		blobCopy[i] = blob[i];
	}*/

	this.encodeTypeAndVal(XML_BLOB, length);

	this.writeBlobArray(blob);
	this.offset += length;
};

var ENCODING_LIMIT_1_BYTE = ((1 << (XML_TT_VAL_BITS)) - 1);
var ENCODING_LIMIT_2_BYTES = ((1 << (XML_TT_VAL_BITS + XML_REG_VAL_BITS)) - 1);
var ENCODING_LIMIT_3_BYTES = ((1 << (XML_TT_VAL_BITS + 2 * XML_REG_VAL_BITS)) - 1);

BinaryXMLEncoder.prototype.numEncodingBytes = function(
		//long
		x) {
	if (x <= ENCODING_LIMIT_1_BYTE) return (1);
	if (x <= ENCODING_LIMIT_2_BYTES) return (2);
	if (x <= ENCODING_LIMIT_3_BYTES) return (3);
	
	var numbytes = 1;
	
	// Last byte gives you XML_TT_VAL_BITS
	// Remainder each give you XML_REG_VAL_BITS
	x = x >>> XML_TT_VAL_BITS;
	while (x != 0) {
        numbytes++;
		x = x >>> XML_REG_VAL_BITS;
	}
	return (numbytes);
};

BinaryXMLEncoder.prototype.writeDateTime = function(
		//String 
		tag, 
		//CCNTime 
		dateTime) {
	
	if(LOG>4)console.log('ENCODING DATE with LONG VALUE');
	if(LOG>4)console.log(dateTime.msec);
	
	//var binarydate = DataUtils.unsignedLongToByteArray( Math.round((dateTime.msec/1000) * 4096)  );
	

	//parse to hex
	var binarydate =  Math.round((dateTime.msec/1000) * 4096).toString(16)  ;

	//HACK
	var binarydate =  DataUtils.toNumbers( '0'.concat(binarydate,'0')) ;

	
	if(LOG>4)console.log('ENCODING DATE with BINARY VALUE');
	if(LOG>4)console.log(binarydate);
	if(LOG>4)console.log('ENCODING DATE with BINARY VALUE(HEX)');
	if(LOG>4)console.log(DataUtils.toHex(binarydate));
	
	this.writeElement(tag, binarydate);
};

// This does not update this.offset.
BinaryXMLEncoder.prototype.writeString = function(input) {
	
    if(typeof input === 'string'){
		//console.log('went here');
    	if(LOG>4) console.log('GOING TO WRITE A STRING');
    	if(LOG>4) console.log(input);
        
        this.ostream.ensureLength(this.offset + input.length);
		for (var i = 0; i < input.length; i++) {
			if(LOG>4) console.log('input.charCodeAt(i)=' + input.charCodeAt(i));
		    this.ostream.array[this.offset + i] = (input.charCodeAt(i));
		}
	}
    else{
		if(LOG>4) console.log('GOING TO WRITE A STRING IN BINARY FORM');
		if(LOG>4) console.log(input);
		
		this.writeBlobArray(input);
    }
    /*
	else if(typeof input === 'object'){
		
	}	
	*/
};


BinaryXMLEncoder.prototype.writeBlobArray = function(
		//Uint8Array 
		blob) {
	
	if(LOG>4) console.log('GOING TO WRITE A BLOB');
    
	this.ostream.set(blob, this.offset);
};


BinaryXMLEncoder.prototype.getReducedOstream = function() {
	return this.ostream.subarray(0, this.offset);
};


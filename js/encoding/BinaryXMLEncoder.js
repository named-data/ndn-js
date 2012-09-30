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


var BinaryXMLEncoder = function BinaryXMLEncoder(){

	this.ostream = new Array(10000);
	
	
	this.offset =0;
	
	this.CODEC_NAME = "Binary";
	
};

BinaryXMLEncoder.prototype.writeUString = function(/*String*/ utf8Content){
	this.encodeUString(this.ostream, utf8Content, XML_UDATA);
};

BinaryXMLEncoder.prototype.writeBlob = function(/*byte []*/ binaryContent
		//, /*int*/ offset, /*int*/ length
		)  {
	
	if(LOG >3) console.log(binaryContent);
	
	this.encodeBlob(this.ostream, binaryContent, this.offset, binaryContent.length);
};

BinaryXMLEncoder.prototype.writeStartElement = function(/*String*/ tag, /*TreeMap<String,String>*/ attributes){

	/*Long*/ dictionaryVal = tag;//stringToTag(tag);
	
	if (null == dictionaryVal) {

		this.encodeUString(this.ostream, tag, XML_TAG);
		
	} else {
		this.encodeTypeAndVal(XML_DTAG, dictionaryVal, this.ostream);
	}
	
	if (null != attributes) {
		this.writeAttributes(attributes); 
	}
};


BinaryXMLEncoder.prototype.writeEndElement = function(){

	this.ostream[this.offset] = XML_CLOSE;
	this.offset+= 1;
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
			this.encodeUString(this.ostream, strAttr, XML_ATTR);
		} else {
			this.encodeTypeAndVal(XML_DATTR, dictionaryAttr, this.ostream);
		}
		// Write value
		this.encodeUString(this.ostream, strValue);
		
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


BinaryXMLEncoder.prototype.writeElement = function(
		//long 
		tag, 
		//byte[] 
		Content,
		//TreeMap<String, String> 
		attributes) {
	
	this.writeStartElement(tag, attributes);
	// Will omit if 0-length
	
	if(typeof Content === 'number') {
		if(LOG>4) console.log('GOING TO WRITE THE NUMBER .charCodeAt(0) ' +Content.toString().charCodeAt(0) );
		if(LOG>4) console.log('GOING TO WRITE THE NUMBER ' +Content.toString() );
		if(LOG>4) console.log('type of number is ' +typeof Content.toString() );
		

		
		this.writeUString(Content.toString());
		//whatever
		
	}
	
	else if(typeof Content === 'string'){
		if(LOG>4) console.log('GOING TO WRITE THE STRING  ' +Content );
		if(LOG>4) console.log('type of STRING is ' +typeof Content );
		
		this.writeUString(Content);
	}
	
	else{
	//else if(typeof Content === 'string'){
		 //console.log('went here');
		//this.writeBlob(Content);
	//}
	if(LOG>4) console.log('GOING TO WRITE A BLOB  ' +Content );
	//else if(typeof Content === 'object'){
		this.writeBlob(Content);
	//}
	}
	
	this.writeEndElement();
}

//TODO

var TypeAndVal = function TypeAndVal(_type,_val) {
	this.type = _type;
	this.val = _val;
	
};

BinaryXMLEncoder.prototype.encodeTypeAndVal = function(
		//int
		type, 
		//long 
		val, 
		//byte [] 
		buf) {
	
	if(LOG>4)console.log('Encoding type '+ type+ ' and value '+ val);
	
	if(LOG>4) console.log('OFFSET IS ' + this.offset );
	
	if ((type > XML_UDATA) || (type < 0) || (val < 0)) {
		throw new Error("Tag and value must be positive, and tag valid.");
	}
	
	// Encode backwards. Calculate how many bytes we need:
	var numEncodingBytes = this.numEncodingBytes(val);
	
	if ((this.offset + numEncodingBytes) > buf.length) {
		throw new Error("Buffer space of " + (buf.length-this.offset) + 
											" bytes insufficient to hold " + 
											numEncodingBytes + " of encoded type and value.");
	}

	// Bottom 4 bits of val go in last byte with tag.
	buf[this.offset + numEncodingBytes - 1] = 
		//(byte)
			(BYTE_MASK &
					(((XML_TT_MASK & type) | 
					 ((XML_TT_VAL_MASK & val) << XML_TT_BITS))) |
					 XML_TT_NO_MORE); // set top bit for last byte
	val = val >>> XML_TT_VAL_BITS;;
	
	// Rest of val goes into preceding bytes, 7 bits per byte, top bit
	// is "more" flag.
	var i = this.offset + numEncodingBytes - 2;
	while ((0 != val) && (i >= this.offset)) {
		buf[i] = //(byte)
				(BYTE_MASK &
						    (val & XML_REG_VAL_MASK)); // leave top bit unset
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

BinaryXMLEncoder.prototype.encodeUString = function(
		//OutputStream 
		ostream, 
		//String 
		ustring, 
		//byte 
		type) {
	
	if ((null == ustring) || (ustring.length == 0)) {
		return;
	}
	
	
	//byte [] data utils
	/*custom*/
	//byte[]
	
	if(LOG>3) console.log("The string to write is ");
	
	if(LOG>3) console.log(ustring);

	//COPY THE STRING TO AVOID PROBLEMS
	strBytes = new Array(ustring.length);
	
	var i = 0;	

	for( ; i<ustring.length; i++) //in InStr.ToCharArray())
	{
		if(LOG>3)console.log("ustring[" + i + '] = ' + ustring[i]);
		strBytes[i] = ustring.charCodeAt(i);
	}
	
	//strBytes = DataUtils.getBytesFromUTF8String(ustring);
	
	this.encodeTypeAndVal(type, 
						(((type == XML_TAG) || (type == XML_ATTR)) ?
								(strBytes.length-1) :
								strBytes.length), ostream);
	
	if(LOG>3) console.log("THE string to write is ");
	
	if(LOG>3) console.log(strBytes);
	
	this.writeString(strBytes,this.offset);
	
	this.offset+= strBytes.length;

};



BinaryXMLEncoder.prototype.encodeBlob = function(
		//OutputStream 
		ostream, 
		//byte [] 
		blob, 
		//int 
		offset, 
		//int 
		length) {


	if ((null == blob) || (length == 0)) {

		return;
	}
	
	if(LOG>4) console.log('LENGTH OF XML_BLOB IS '+length);
	
	
	blobCopy = new Array(blob.Length);
	var i = 0;
	for( ;i<blob.length;i++) //in InStr.ToCharArray())
	{
		blobCopy[i] = blob[i];
	}

	this.encodeTypeAndVal(XML_BLOB, length, ostream,offset);
	
	if (null != blob) {

		this.writeBlobArray(blobCopy,this.offset);
		this.offset += length;
	}
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

BinaryXMLEncoder.prototype.writeString = function(
		//String 
		input,
		//CCNTime 
		offset) {
	
    if(typeof input === 'string'){
		//console.log('went here');
    	if(LOG>4) console.log('GOING TO WRITE A STRING');
    	if(LOG>4) console.log(input);
        
		for (var i = 0; i < input.length; i++) {
			if(LOG>4) console.log('input.charCodeAt(i)=' + input.charCodeAt(i));
		    this.ostream[this.offset+i] = (input.charCodeAt(i));
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
		//String 
		Blob,
		//CCNTime 
		offset) {
	
	if(LOG>4) console.log('GOING TO WRITE A BLOB');
    
	for (var i = 0; i < Blob.length; i++) {
	    this.ostream[this.offset+i] = Blob[i];
	}
	
};



BinaryXMLEncoder.prototype.getReducedOstream = function() {
	
	return this.ostream.slice(0,this.offset);
	
};


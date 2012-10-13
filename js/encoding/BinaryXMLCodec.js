/*
 * This class is used to encode and decode binary elements ( blog, type/value pairs)
 * 
 * @author: ucla-cs
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


var TypeAndVal = function TypeAndVal(_type,_val) {
	this.type = _type;
	this.val = _val;
	
};

var BinaryXMLCodec = function BinaryXMLCodec(){
	this.CODEC_NAME = "Binary";
};
    


BinaryXMLCodec.prototype.encodeTypeAndValOffset = function(
	//int
	type,
	//long
	val,
	//byte []
	buf,
	//int
	offset) {
	
	if ((type > XML_UDATA) || (type < 0) || (val < 0)) {
		throw new Error("Tag and value must be positive, and tag valid.");
	}
	
	// Encode backwards. Calculate how many bytes we need:
	var/*int*/ numEncodingBytes = numEncodingBytes(val);
	
	if ((offset + numEncodingBytes) > buf.length) {
		throw new Error("Buffer space of " + (buf.length-offset) + 
											" bytes insufficient to hold " + 
											numEncodingBytes + " of encoded type and value.");
	}
	

	buf[offset + numEncodingBytes - 1] = 
		(BYTE_MASK &
					(((XML_TT_MASK & type) | 
					 ((XML_TT_VAL_MASK & val) << XML_TT_BITS))) |
					 XML_TT_NO_MORE); 
	val = val >>> XML_TT_VAL_BITS;;

	var /*int*/ i = offset + numEncodingBytes - 2;
	while ((0 != val) && (i >= offset)) {
		buf[i] = (BYTE_MASK &
						    (val & XML_REG_VAL_MASK)); 
		val = val >>> XML_REG_VAL_BITS;
		--i;
	}
	
	return numEncodingBytes;
};


BinaryXMLCodec.prototype.encodeTypeAndVal = function(
		//int
		type, 
		//long 
		val, 
		//byte [] 
		buf, 
		//int 
		offset) {
	
	if ((type > XML_UDATA) || (type < 0) || (val < 0)) {
		throw new Error("Tag and value must be positive, and tag valid.");
	}
	
	// Encode backwards. Calculate how many bytes we need:
	//int
	var numEncodingBytes = numEncodingBytes(val);
	
	if ((offset + numEncodingBytes) > buf.length) {
		throw new Error("Buffer space of " + (buf.length-offset) + 
											" bytes insufficient to hold " + 
											numEncodingBytes + " of encoded type and value.");
	}
	
	// Bottom 4 bits of val go in last byte with tag.
	buf[offset + numEncodingBytes - 1] = 
		//(byte)
			(BYTE_MASK &
					(((XML_TT_MASK & type) | 
					 ((XML_TT_VAL_MASK & val) << XML_TT_BITS))) |
					 XML_TT_NO_MORE); // set top bit for last byte
	val = val >>> XML_TT_VAL_BITS;;
	
	// Rest of val goes into preceding bytes, 7 bits per byte, top bit
	// is "more" flag.
	var i = offset + numEncodingBytes - 2;
	while ((0 != val) && (i >= offset)) {
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
	
	return numEncodingBytes;
}


	
BinaryXMLCodec.prototype.decodeTypeAndVal = function(
		/*InputStream*/
		istream) {
	
	/*int*/next;
	/*int*/type = -1;
	/*long*/val = 0;
	/*boolean*/more = true;

	do {
		next = istream.read();
		
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
		
	} while (more);
	
	return new TypeAndVal(type, val);
};

BinaryXMLCodec.prototype.encodeUString = function(
		//OutputStream 
		ostream, 
		//String 
		ustring, 
		//byte 
		type,
		offset) {
	
	// We elide the encoding of a 0-length UString
	if ((null == ustring) || (ustring.length == 0)) {
		//if (Log.isLoggable(Log.FAC_ENCODING, Level.FINER))
			//Log.finer(Log.FAC_ENCODING, "Eliding 0-length UString.");
		return;
	}
	
	//byte [] data utils
	/*custom*/
	//byte[]
	strBytes = new Array(ustring.Length);
	var i = 0;
	for( ;i<ustring.lengh;i++) //in InStr.ToCharArray())
	{
		strBytes[i] = ustring[i];
	}
	//strBytes = DataUtils.getBytesFromUTF8String(ustring);
	
	this.encodeTypeAndVal(type, 
						(((type == XML_TAG) || (type == XML_ATTR)) ?
								(strBytes.length-1) :
								strBytes.length), ostream);
	//
	//console.log(strBytes.toString());
	
	ostream.write(strBytes.toString(),offset);
	
	// 
};

BinaryXMLCodec.prototype.encodeBlob = function(
		//OutputStream 
		ostream, 
		//byte [] 
		blob, 
		//int 
		offset, 
		//int 
		length) {
	// We elide the encoding of a 0-length blob
	if ((null == blob) || (length == 0)) {

		return;
	}
	
	encodeTypeAndVal(XML_BLOB, length, ostream,offset);
	if (null != blob) {
		ostream.write(blob, this.offset, length);
		this.offset += length;
	}
};


var ENCODING_LIMIT_1_BYTE = ((1 << (XML_TT_VAL_BITS)) - 1);
var ENCODING_LIMIT_2_BYTES = ((1 << (XML_TT_VAL_BITS + XML_REG_VAL_BITS)) - 1);
var ENCODING_LIMIT_3_BYTES = ((1 << (XML_TT_VAL_BITS + 2 * XML_REG_VAL_BITS)) - 1);

var numEncodingBytes = function(
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
}

//TODO
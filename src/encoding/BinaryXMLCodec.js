
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
	
var bits_11 = 0x0000007FFL;
var bits_18 = 0x00003FFFFL;
var bits_32 = 0x0FFFFFFFFL;


var TypeAndVal = function TypeAndVal(_type,_val) {
	this.type = _type;
	this.val = _val;
	
};
exports.TypeAndVal = TypeAndVal;

var BinaryXMLCodec = function BinaryXMLCodec(){
	
	this.CODEC_NAME = "Binary";
			


};

exports.BinaryXMLCodec = BinaryXMLCodec;


    
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
		throw new Exception("Tag and value must be positive, and tag valid.");
	}
	
	// Encode backwards. Calculate how many bytes we need:
	int numEncodingBytes = numEncodingBytes(val);
	
	if ((offset + numEncodingBytes) > buf.length) {
		throw new Exception("Buffer space of " + (buf.length-offset) + 
											" bytes insufficient to hold " + 
											numEncodingBytes + " of encoded type and value.");
	}
	

	buf[offset + numEncodingBytes - 1] = 
		(BYTE_MASK &
					(((XML_TT_MASK & type) | 
					 ((XML_TT_VAL_MASK & val) << XML_TT_BITS))) |
					 XML_TT_NO_MORE); 
	val = val >>> XML_TT_VAL_BITS;;

	int i = offset + numEncodingBytes - 2;
	while ((0 != val) && (i >= offset)) {
		buf[i] = (BYTE_MASK &
						    (val & XML_REG_VAL_MASK)); 
		val = val >>> XML_REG_VAL_BITS;
		--i;
	}
	
	return numEncodingBytes;
};
	
BinaryXMLCodec.prototype.decodeTypeAndVal = function(
		/*InputStream*/
		istream) {
	
	int next;
	int type = -1;
	long val = 0;
	boolean more = true;

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

//TODO
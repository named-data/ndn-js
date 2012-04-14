
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

//var BinaryXMLCodec = require('./BinaryXMLCodec').BinaryXMLCodec;

//var codec = new BinaryXMLCodec();


var BinaryXMLEncoder = function BinaryXMLEncoder(){

	this.ostream = new Array(1024);
	
	this.offset =0;
	
	this.CODEC_NAME = "Binary";
	
};


/*BinaryXMLEncoder.prototype.beginEncoding = function() {
	this.ostream = new Buffer(1024);
	this.offset = 0;
};

BinaryXMLEncoder.prototype.endEncoding = function(){
	//this.ostream.end();
};*/

BinaryXMLEncoder.prototype.writeUString = function(/*String*/ utf8Content){
	this.encodeUString(this.ostream, utf8Content);
};

BinaryXMLEncoder.prototype.writeBlob = function(/*byte []*/ binaryContent
		//, /*int*/ offset, /*int*/ length
		)  {
	//console.log(binaryContent);
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
	//console.log(XML_CLOSE);
	//console.log(tagToString(XML_CLOSE));
	//this.ostream.writeUInt8(  XML_CLOSE  ,this.offset);
	this.ostream[this.offset] = XML_CLOSE;
	this.offset+= 1;
}

BinaryXMLEncoder.prototype.writeAttributes = function(/*TreeMap<String,String>*/ attributes) {
	
	if (null == attributes) {
		return;
	}

	// the keySet of a TreeMap is sorted.
	/*Set<String> keySet = attributes.keySet();
	Iterator<String> it = keySet.iterator();*/
	
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
		binaryContent,
		//TreeMap<String, String> 
		attributes) {
	this.writeStartElement(tag, attributes);
	// Will omit if 0-length
	
	this.writeBlob(binaryContent);
	this.writeEndElement();
}

//TODO
//console.log(stringToTag(0));









var TypeAndVal = function TypeAndVal(_type,_val) {
	this.type = _type;
	this.val = _val;
	
};


    
/*BinaryXMLEncoder.prototype.encodeTypeAndValOffset = function(
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
	//int
	var numEncodingBytes = numEncodingBytes(val);
	
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
	//int
	var  i = offset + numEncodingBytes - 2;
	while ((0 != val) && (i >= offset)) {
		buf[i] = (BYTE_MASK &
						    (val & XML_REG_VAL_MASK)); 
		val = val >>> XML_REG_VAL_BITS;
		--i;
	}
	
	return numEncodingBytes;
};*/

//BinaryXMLCodec.prototype.encodeTypeAndVal =  function(
	//	//final int 
		//type, 
		//final long 
		//value, 
		//final OutputStream 
		//ostream,
		//offset){
	
    /*
    We exploit the fact that encoding is done from the right, so this actually means
    there is a deterministic encoding from a long to a Type/Value pair:
    
    |    0    |    1    |    2    |    3    |    4    |    5    |    6    |    7    |
    |ABCD.EFGH|IJKL.MNOP|QRST.UVWX|YZ01.2345|6789.abcd|efgh.ijkl|mnop.qrst|uvwx.yz@#
    
           60>       53>       46>       39>       32>       25>       18>       11>        4>
    |_000.ABCD|_EFG.HIJK|_LMN.OPQR|_STU.VWXY|_Z01.2345|_678.9abc|_defg.hij|_klm.nopq|_rst.uvwx|_yz@#___
    
    What we want to do is compute the result in MSB order and write it directly
    to the channel without any intermediate form.
    */

   //var/*int*/  bits;
   //var/*int*/  count = 0;
   
   // once we start writing bits, we keep writing bits even if they are "0"
  // var/*bool*/ writing = false;
   
   // a few heuristic to catch the small-bit length patterns
   /*if( value < 0 || value > 15 ) {
       var start = 60;
       if( 0 <= value ) {
    	   if( value < bits_11 )
    		   start = 4;
    	   else if( value < bits_18 )
               start = 11;
           else if( value < bits_32 )
               start = 25;
       }
       
       for( var i = start; i >= 4; i -= 7) {
           bits =  (value >>> i) & BinaryXMLCodec.XML_REG_VAL_MASK;
           if( bits != 0 || writing ) {
               ostream.write(bits);
               count++;
               writing = true;
           }
       }
   }
   
   // Explicit computation of the bottom byte
   bits = type & BinaryXMLCodec.XML_TT_MASK;
   var bottom4 = value & BinaryXMLCodec.XML_TT_VAL_MASK;
   bits |= bottom4 << BinaryXMLCodec.XML_TT_BITS;
   // the bottom byte always has the NO_MORE flag
   bits |= BinaryXMLCodec.XML_TT_NO_MORE;

   //console.log(ostream.constructor.name);
   //console.log(ostream);
   
   //ostream.writable = true;
   //console.log(ostream.)
   ostream.write(bits.toString());
   
   count++;

//	byte [] encoding = encodeTypeAndVal(tag, val);
//	ostream.write(encoding);
	return count;

}*/


BinaryXMLEncoder.prototype.encodeTypeAndVal = function(
		//int
		type, 
		//long 
		val, 
		//byte [] 
		buf) {
	
	console.log('Encoding type '+ type+ ' and value '+ val);
	
	if ((type > XML_UDATA) || (type < 0) || (val < 0)) {
		throw new Exception("Tag and value must be positive, and tag valid.");
	}
	
	// Encode backwards. Calculate how many bytes we need:
	var numEncodingBytes = this.numEncodingBytes(val);
	
	if ((this.offset + numEncodingBytes) > buf.length) {
		throw new Exception("Buffer space of " + (buf.length-this.offset) + 
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
		throw new Exception( "This should not happen: miscalculated encoding");
		//Log.warning(Log.FAC_ENCODING, "This should not happen: miscalculated encoding length, have " + val + " left.");
	}
	this.offset+= numEncodingBytes;
	console.log('offset increased after tag to  '+this.offset);
	
	return numEncodingBytes;
};

BinaryXMLEncoder.prototype.encodeUString = function(
		//OutputStream 
		ostream, 
		//String 
		ustring, 
		//byte 
		type) {
	
	// We elide the encoding of a 0-length UString
	if ((null == ustring) || (ustring.length == 0)) {
		//if (Log.isLoggable(Log.FAC_ENCODING, Level.FINER))
			//Log.finer(Log.FAC_ENCODING, "Eliding 0-length UString.");
		return;
	}
	
	console.log('Writting String to  '+ ustring);
	
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
	
	//console.log(strBytes.toString());

	ostream.write(strBytes.toString(),this.offset);
	this.offset+= strBytes.length;
	console.log('offset increased after String to '+this.offset);
	// 
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

	console.log('Writting Blob   ');
	console.log('length is '+ length);
	
	// We elide the encoding of a 0-length blob
	if ((null == blob) || (length == 0)) {

		return;
	}
	
	
	this.encodeTypeAndVal(XML_BLOB, length, ostream,offset);
	
	if (null != blob) {
		//console.log(blob);
		//maybe blog.t
		ostream.write(blob.toString(), this.offset);
		this.offset += length;
		console.log('offset increased after blob to  '+this.offset);
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
	this.writeElement(tag, dateTime.toBinaryTime());
};

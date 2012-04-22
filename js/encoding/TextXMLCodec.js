//TODO INCOMPLETE
/*
 * @author: ucla-cs
 * 
 * Encodes CCN object into xml tags
 */
var DataUtils = require('./DataUtils').DataUtils;
	
 	var /*DateFormat*/ canonicalWriteDateFormat = null;
	var /* DateFormat*/ canonicalReadDateFormat = null;
    var /*String*/ PAD_STRING = "000000000";
	var /*int*/ NANO_LENGTH = 9;

var TextXMLCodec =  function TextXMLCodec(){

	this.CCN_NAMESPACE = "http://www.parc.com/ccn"; // String
	this.CCN_PREFIX = "ccn";	// String
	this.CODEC_NAME = "Text";// String
	this.BINARY_ATTRIBUTE = "ccnbencoding";// String
	this.BINARY_ATTRIBUTE_VALUE = "base64Binary";// String


};

//returns a string

TextXMLCodec.protpotype.codecName = function() { return this.CODEC_NAME; }	;

//returns a string
TextXMLCodec.protottype.encodeBinaryElement = function(/*byte []*/ element) {
		if ((null == element) || (0 == element.length)) 
			return new String("");
		return new String(DataUtils.base64Encode(element));
	};
	
/* returns a string */
TextXMLCodec.prototype.encodeBinaryElement = function(/*byte []*/ element, /*int*/ offset, /*int*/ length) {
		if ((null == element) || (0 == element.length)) 
			return new String("");
		ByteBuffer bbuf = ByteBuffer.wrap(element, offset, length);
		return new String(DataUtils.base64Encode(bbuf.array()));
	};

/*returns a byte array*/
TextXMLCodec.prototype.decodeBinaryElement = function(/*String*/ element) {
		if ((null == element) || (0 == element.length()))
			return new byte[0];
		return DataUtils.base64Decode(element.getBytes());
	}; 

	
/*
	Decode Data
*/
	

/*
	Encode Date
*/ 
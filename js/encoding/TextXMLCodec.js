//TODO INCOMPLETE
/*
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * 
 * Encodes NDN object into xml tags
 */
var DataUtils = require('./DataUtils').DataUtils;
	
 	var /*DateFormat*/ canonicalWriteDateFormat = null;
	var /* DateFormat*/ canonicalReadDateFormat = null;
    var /*String*/ PAD_STRING = "000000000";
	var /*int*/ NANO_LENGTH = 9;

var TextXMLCodec =  function TextXMLCodec(){

	this.NDN_NAMESPACE = "http://www.parc.com/ndn"; // String
	this.NDN_PREFIX = "ndn";	// String
	this.CODEC_NAME = "Text";// String
	this.BINARY_ATTRIBUTE = "ndnbencoding";// String
	this.BINARY_ATTRIBUTE_VALUE = "base64Binary";// String


};


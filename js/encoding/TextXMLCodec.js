//TODO INCOMPLETE
/*
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
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


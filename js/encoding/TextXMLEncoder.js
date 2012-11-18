//TODO INCOMPLETE
/*
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * 
 * Encodes CCN object into xml
 */

var Stream = require('stream').Stream;
var TextXMLCodec = require('TextXMLCodec').TextXMLCodec;




var TextXMLEncoder  = function TextXMLEncoder(){


	this.ostream = new String();
};



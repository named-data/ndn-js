
/*
 * This class contains utilities to help parse the data
 * author: ucla-cs
 */
 
var DataUtils = function DataUtils(){
	
	
};


/*
 * NOTE THIS IS CURRENTLY NOT BEHING USED
 * 
 */

  var keyStr = "ABCDEFGHIJKLMNOP" +
               "QRSTUVWXYZabcdef" +
               "ghijklmnopqrstuv" +
               "wxyz0123456789+/" +
               "=";

DataUtils.stringtoBase64=function stringtoBase64(input) {
     input = escape(input);
     var output = "";
     var chr1, chr2, chr3 = "";
     var enc1, enc2, enc3, enc4 = "";
     var i = 0;

     do {
        chr1 = input.charCodeAt(i++);
        chr2 = input.charCodeAt(i++);
        chr3 = input.charCodeAt(i++);

        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;

        if (isNaN(chr2)) {
           enc3 = enc4 = 64;
        } else if (isNaN(chr3)) {
           enc4 = 64;
        }

        output = output +
           keyStr.charAt(enc1) +
           keyStr.charAt(enc2) +
           keyStr.charAt(enc3) +
           keyStr.charAt(enc4);
        chr1 = chr2 = chr3 = "";
        enc1 = enc2 = enc3 = enc4 = "";
     } while (i < input.length);

     return output;
  }

DataUtils.base64toString = function base64toString(input) {
     var output = "";
     var chr1, chr2, chr3 = "";
     var enc1, enc2, enc3, enc4 = "";
     var i = 0;

     // remove all characters that are not A-Z, a-z, 0-9, +, /, or =
     var base64test = /[^A-Za-z0-9\+\/\=]/g;
     if (base64test.exec(input)) {
        alert("There were invalid base64 characters in the input text.\n" +
              "Valid base64 characters are A-Z, a-z, 0-9, '+', '/',and '='\n" +
              "Expect errors in decoding.");
     }
     input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

     do {
        enc1 = keyStr.indexOf(input.charAt(i++));
        enc2 = keyStr.indexOf(input.charAt(i++));
        enc3 = keyStr.indexOf(input.charAt(i++));
        enc4 = keyStr.indexOf(input.charAt(i++));

        chr1 = (enc1 << 2) | (enc2 >> 4);
        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        chr3 = ((enc3 & 3) << 6) | enc4;

        output = output + String.fromCharCode(chr1);

        if (enc3 != 64) {
           output = output + String.fromCharCode(chr2);
        }
        if (enc4 != 64) {
           output = output + String.fromCharCode(chr3);
        }

        chr1 = chr2 = chr3 = "";
        enc1 = enc2 = enc3 = enc4 = "";

     } while (i < input.length);

     return unescape(output);
  };

//byte [] 
DataUtils.prototype.unsignedLongToByteArray= function( value) {
	if( 0 == value )
		return [0];

	if( 0 <= value && value <= 0x00FF ) {
		//byte [] 
		bb = new Array[1];
		bb[0] = (value & 0x00FF);
		return bb;
	}

	
	//byte [] 
	out = null;
	//int
	var offset = -1;
	for(var i = 7; i >=0; --i) {
		//byte
		b = ((value >> (i * 8)) & 0xFF);
		if( out == null && b != 0 ) {
			out = new byte[i+1];
			offset = i;
		}
		if( out != null )
			out[ offset - i ] = b;
	}
	return out;
}


var utf8 = {}

utf8.toByteArray = function(str) {
    var byteArray = [];
    for (var i = 0; i < str.length; i++)
        if (str.charCodeAt(i) <= 0x7F)
            byteArray.push(str.charCodeAt(i));
        else {
            var h = encodeURIComponent(str.charAt(i)).substr(1).split('%');
            for (var j = 0; j < h.length; j++)
                byteArray.push(parseInt(h[j], 16));
        }
    return byteArray;
};

utf8.parse = function(byteArray) {
    var str = '';
    for (var i = 0; i < byteArray.length; i++)
        str +=  byteArray[i] <= 0x7F?
                byteArray[i] === 0x25 ? "%25" : // %
                String.fromCharCode(byteArray[i]) :
                "%" + byteArray[i].toString(16).toUpperCase();
    return decodeURIComponent(str);
};


//http://ejohn.org/blog/numbers-hex-and-colors/
function toHex(arguments){
  //console.log(arguments);
  var ret = "";
  for ( var i = 0; i < arguments.length; i++ )
    ret += (arguments[i] < 16 ? "0" : "") + arguments[i].toString(16);
  return ret.toUpperCase();
}

//DOES NOT SEEM TO WORK
function toString(arguments){
  //console.log(arguments);
  var ret = "";
  for ( var i = 0; i < arguments.length; i++ )
    ret += String.fromCharCode(arguments[i]);
  return ret;
}

function toNumbers( str ){
	if(typeof str =='string'){
		  var ret = [];
		   str.replace(/(..)/g, function(str){
		    ret.push( parseInt( str, 16 ) );
		  });
		   return ret;
    }
}

function toNumbersFromString( str ){
	var bytes = new Array(str.length);
	for(var i=0;i<str.length;i++)
		bytes[i] = str.charCodeAt(i);
	return bytes;
}
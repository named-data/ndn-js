/**
 * This class contains utilities to help parse the data
 * author: Meki Cheraoui, Jeff Thompson
 * See COPYING for copyright and distribution information.
 */
 
var DataUtils = function DataUtils(){
	
	
};


/*
 * NOTE THIS IS CURRENTLY NOT BEHING USED
 * 
 */

DataUtils.keyStr = "ABCDEFGHIJKLMNOP" +
               "QRSTUVWXYZabcdef" +
               "ghijklmnopqrstuv" +
               "wxyz0123456789+/" +
               "=";

               
/**
 * Raw String to Base 64
 */
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
           DataUtils.keyStr.charAt(enc1) +
           DataUtils.keyStr.charAt(enc2) +
           DataUtils.keyStr.charAt(enc3) +
           DataUtils.keyStr.charAt(enc4);
        chr1 = chr2 = chr3 = "";
        enc1 = enc2 = enc3 = enc4 = "";
     } while (i < input.length);

     return output;
  }

/**
 * Base 64 to Raw String 
 */
DataUtils.base64toString = function base64toString(input) {
     var output = "";
     var chr1, chr2, chr3 = "";
     var enc1, enc2, enc3, enc4 = "";
     var i = 0;

     // remove all characters that are not A-Z, a-z, 0-9, +, /, or =
     var base64test = /[^A-Za-z0-9\+\/\=]/g;
     /* Test for invalid characters. */
     if (base64test.exec(input)) {
        alert("There were invalid base64 characters in the input text.\n" +
              "Valid base64 characters are A-Z, a-z, 0-9, '+', '/',and '='\n" +
              "Expect errors in decoding.");
     }
     
     input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

     do {
        enc1 = DataUtils.keyStr.indexOf(input.charAt(i++));
        enc2 = DataUtils.keyStr.indexOf(input.charAt(i++));
        enc3 = DataUtils.keyStr.indexOf(input.charAt(i++));
        enc4 = DataUtils.keyStr.indexOf(input.charAt(i++));

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

/**
 * NOT WORKING!!!!!
 * 
 * Unsiged Long Number to Byte Array
 */
	
 /*
DataUtils.unsignedLongToByteArray= function( value) {
	
	if(LOG>4)console.log('INPUT IS '+value);
	
	if( 0 == value )
		return [0];

	if( 0 <= value && value <= 0x00FF ) {
		//byte [] 
		var bb = new Array(1);
		bb[0] = (value & 0x00FF);
		return bb;
	}

	if(LOG>4) console.log('type of value is '+typeof value);
	if(LOG>4) console.log('value is '+value);
	//byte [] 
	var out = null;
	//int
	var offset = -1;
	for(var i = 7; i >=0; --i) {
		//byte
		console.log(i);
		console.log('value is '+value);
		console.log('(value >> (i * 8)) '+ (value >> (i * 8))  );
		console.log(' ((value >> (i * 8)) & 0xFF) '+ ((value >> (i * 8)) & 0xFF)  );

		var b = ((value >> (i * 8)) & 0xFF)  ;
		
		if(LOG>4) console.log('b is '+b);
		
		if( out == null && b != 0 ) {
			//out = new byte[i+1];
			out = new Array(i+1);
			offset = i;
		}
		
		if( out != null )
			out[ offset - i ] = b;
	}
	if(LOG>4)console.log('OUTPUT IS ');
	if(LOG>4)console.log(out);
	return out;
}
*/
	
/**
 * NOT WORKING!!!!!
 * 
 * Unsiged Long Number to Byte Array
 *//*
DataUtils.byteArrayToUnsignedLong = function(//final byte [] 
	src) {
		if(LOG>4) console.log('INPUT IS ');
		if(LOG>4) console.log(src);
		
		var value = 0;
		for(var i = 0; i < src.length; i++) {
			value = value << 8;
			// Java will assume the byte is signed, so extend it and trim it.
			
			
			var b = ((src[i]) & 0xFF );
			value |= b;
		}
		
		if(LOG>4) console.log('OUTPUT IS ');
		
		if(LOG>4) console.log(value);

		return value;
	}*/


/**
 * Hex String to Byte Array
 */
	//THIS IS NOT WORKING
/*
DataUtils.HexStringtoByteArray = function(str) {
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
*/

/**
 * Uint8Array to Hex String
 */
//http://ejohn.org/blog/numbers-hex-and-colors/
DataUtils.toHex = function(args){
	if (LOG>4) console.log('ABOUT TO CONVERT '+ args);
	//console.log(args);
  	var ret = "";
  	for ( var i = 0; i < args.length; i++ )
    	ret += (args[i] < 16 ? "0" : "") + args[i].toString(16);
  	if (LOG>4) console.log('Converted to: ' + ret);
  	return ret; //.toUpperCase();
}

/**
 * Raw string to hex string.
 */
DataUtils.stringToHex = function(args){
	var ret = "";
	for (var i = 0; i < args.length; ++i) {
		var value = args.charCodeAt(i);
		ret += (value < 16 ? "0" : "") + value.toString(16);
	}
	return ret;
}

/**
 * Uint8Array to raw string.
 */
DataUtils.toString = function(args){
  //console.log(arguments);
  var ret = "";
  for ( var i = 0; i < args.length; i++ )
    ret += String.fromCharCode(args[i]);
  return ret;
}

/**
 * Hex String to Uint8Array.
 */
DataUtils.toNumbers = function(str) {
	if (typeof str == 'string') {
		var ret = new Uint8Array(Math.floor(str.length / 2));
        var i = 0;
		str.replace(/(..)/g, function(str) {
		    ret[i++] = parseInt(str, 16);
		});
		return ret;
    }
}

/**
 * Hex String to raw string.
 */
DataUtils.hexToRawString = function(str) {
    if(typeof str =='string') {
		var ret = "";
		str.replace(/(..)/g, function(s) {
			ret += String.fromCharCode(parseInt(s, 16));
		});
		return ret;
    }
}

/**
 * Raw String to Uint8Array.
 */
DataUtils.toNumbersFromString = function(str) {
	var bytes = new Uint8Array(str.length);
	for(var i=0;i<str.length;i++)
		bytes[i] = str.charCodeAt(i);
	return bytes;
}

/*
 * Encode str as utf8 and return as Uint8Array.
 * TODO: Use TextEncoder when available.
 */
DataUtils.stringToUtf8Array = function(str) {
    return DataUtils.toNumbersFromString(str2rstr_utf8(str));
}

/*
 * arrays is an array of Uint8Array. Return a new Uint8Array which is the concatenation of all.
 */
DataUtils.concatArrays = function(arrays) {
    var totalLength = 0;
	for (var i = 0; i < arrays.length; ++i)
        totalLength += arrays[i].length;
    
    var result = new Uint8Array(totalLength);
    var offset = 0;
	for (var i = 0; i < arrays.length; ++i) {
        result.set(arrays[i], offset);
        offset += arrays[i].length;
    }
    return result;
    
}
 
// TODO: Take Uint8Array and use TextDecoder when available.
DataUtils.decodeUtf8 = function (utftext) {
		var string = "";
		var i = 0;
		var c = 0;
        var c1 = 0;
        var c2 = 0;
 
		while ( i < utftext.length ) {
 
			c = utftext.charCodeAt(i);
 
			if (c < 128) {
				string += String.fromCharCode(c);
				i++;
			}
			else if((c > 191) && (c < 224)) {
				c2 = utftext.charCodeAt(i+1);
				string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
				i += 2;
			}
			else {
				c2 = utftext.charCodeAt(i+1);
				var c3 = utftext.charCodeAt(i+2);
				string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
				i += 3;
			}
 
		}
 
		return string;
	};

//NOT WORKING
/*
DataUtils.getUTF8StringFromBytes = function(bytes) {
	
	bytes = toString(bytes);

    var ix = 0;
 
    if( bytes.slice(0,3) == "\xEF\xBB\xBF") {
        ix = 3;
    }
 
    var string = "";
    for( ; ix < bytes.length; ix++ ) {
        var byte1 = bytes[ix].charCodeAt(0);
        if( byte1 < 0x80 ) {
            string += String.fromCharCode(byte1);
        } else if( byte1 >= 0xC2 && byte1 < 0xE0 ) {
            var byte2 = bytes[++ix].charCodeAt(0);
            string += String.fromCharCode(((byte1&0x1F)<<6) + (byte2&0x3F));
        } else if( byte1 >= 0xE0 && byte1 < 0xF0 ) {
            var byte2 = bytes[++ix].charCodeAt(0);
            var byte3 = bytes[++ix].charCodeAt(0);
            string += String.fromCharCode(((byte1&0xFF)<<12) + ((byte2&0x3F)<<6) + (byte3&0x3F));
        } else if( byte1 >= 0xF0 && byte1 < 0xF5) {
            var byte2 = bytes[++ix].charCodeAt(0);
            var byte3 = bytes[++ix].charCodeAt(0);
            var byte4 = bytes[++ix].charCodeAt(0);
            var codepoint = ((byte1&0x07)<<18) + ((byte2&0x3F)<<12)+ ((byte3&0x3F)<<6) + (byte4&0x3F);
            codepoint -= 0x10000;
            string += String.fromCharCode(
                (codepoint>>10) + 0xD800,
                (codepoint&0x3FF) + 0xDC00
            );
        }
    }
 
    return string;
}*/

/**
 * Return true if a1 and a2 are the same length with equal elements.
 */
DataUtils.arraysEqual = function(a1, a2){
    if (a1.length != a2.length)
        return false;
    
    for (var i = 0; i < a1.length; ++i) {
        if (a1[i] != a2[i])
            return false;
    }

    return true;
};

/*
 * Convert the big endian Uint8Array to an unsigned int.
 * Don't check for overflow.
 */
DataUtils.bigEndianToUnsignedInt = function(bytes) {
    var result = 0;
    for (var i = 0; i < bytes.length; ++i) {
        result <<= 8;
        result += bytes[i];
    }
    return result;
};

/*
 * Convert the int value to a new big endian Uint8Array and return.
 * If value is 0 or negative, return Uint8Array(0). 
 */
DataUtils.nonNegativeIntToBigEndian = function(value) {
    value = Math.round(value);
    if (value <= 0)
        return new Uint8Array(0);
    
    // Assume value is not over 64 bits.
    var size = 8;
    var result = new Uint8Array(size);
    var i = 0;
    while (value != 0) {
        ++i;
        result[size - i] = value & 0xff;
        value >>= 8;
    }
    return result.subarray(size - i, size);
};

/*
 * Modify array to randomly shuffle the elements.
 */
DataUtils.shuffle = function(array) {
    for (var i = array.length - 1; i >= 1; --i) {
        // j is from 0 to i.
        var j = Math.floor(Math.random() * (i + 1));
        var temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
}

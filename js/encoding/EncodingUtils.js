/**
 * This file contains utilities to help encode and decode NDN objects.
 * author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 */

/**
 * An EncodingUtils has static methods for encoding data.
 * @constructor
 */
var EncodingUtils = function EncodingUtils(){
};

exports.EncodingUtils = EncodingUtils;

EncodingUtils.encodeToHexInterest = function(interest){
  return DataUtils.toHex(interest.encode());
}

EncodingUtils.encodeToHexContentObject = function(contentObject) {
  return DataUtils.toHex(contentObject.encode());
}

EncodingUtils.encodeForwardingEntry = function(co) {
	var enc = new BinaryXMLEncoder();
 
	co.to_ndnb(enc);
	
	var bytes = enc.getReducedOstream();

	return bytes;

	
}

EncodingUtils.decodeHexFaceInstance = function(result){
	
	var numbers = DataUtils.toNumbers(result);
			
	
	var decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODING HEX FACE INSTANCE  \n'+numbers);

	var faceInstance = new FaceInstance();

	faceInstance.from_ndnb(decoder);

	return faceInstance;
	
}

EncodingUtils.decodeHexInterest = function(input){
	var interest = new Interest();
	interest.decode(DataUtils.toNumbers(input));
	return interest;
}

EncodingUtils.decodeHexContentObject = function(input){
	var contentObject = new ContentObject();
	contentObject.decode(DataUtils.toNumbers(input));
	return contentObject;
}

EncodingUtils.decodeHexForwardingEntry = function(result){
	var numbers = DataUtils.toNumbers(result);

	var decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODED HEX FORWARDING ENTRY \n'+numbers);
	
	var forwardingEntry = new ForwardingEntry();

	forwardingEntry.from_ndnb(decoder);

	return forwardingEntry;
	
}

/**
 * Decode the Buffer array which holds SubjectPublicKeyInfo and return an RSAKey.
 */
EncodingUtils.decodeSubjectPublicKeyInfo = function(array) {
    var hex = DataUtils.toHex(array).toLowerCase();
    var a = _x509_getPublicKeyHexArrayFromCertHex(hex, _x509_getSubjectPublicKeyPosFromCertHex(hex, 0));
    var rsaKey = new RSAKey();
    rsaKey.setPublic(a[0], a[1]);
    return rsaKey;
}

/**
 * Return a user friendly HTML string with the contents of co.
 * This also outputs to console.log.
 */
EncodingUtils.contentObjectToHtml = function(/* ContentObject */ co) {
    var output ="";
			
    if(co==-1)
	output+= "NO CONTENT FOUND"
    else if (co==-2)
	output+= "CONTENT NAME IS EMPTY"
    else{
	if(co.name!=null && co.name.components!=null){
	    output+= "NAME: " + co.name.to_uri();
        
	    output+= "<br />";
	    output+= "<br />";
	}
	
	if(co.content !=null){
	    output += "CONTENT(ASCII): "+ DataUtils.toString(co.content);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.content !=null){
	    output += "CONTENT(hex): "+ DataUtils.toHex(co.content);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.signature !=null && co.signature.digestAlgorithm!=null){
	    output += "DigestAlgorithm (hex): "+ DataUtils.toHex(co.signature.digestAlgorithm);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.signature !=null && co.signature.witness!=null){
	    output += "Witness (hex): "+ DataUtils.toHex(co.signature.witness);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.signature !=null && co.signature.signature!=null){
	    output += "Signature(hex): "+ DataUtils.toHex(co.signature.signature);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.signedInfo !=null && co.signedInfo.publisher!=null && co.signedInfo.publisher.publisherPublicKeyDigest!=null){
	    output += "Publisher Public Key Digest(hex): "+ DataUtils.toHex(co.signedInfo.publisher.publisherPublicKeyDigest);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.signedInfo !=null && co.signedInfo.timestamp!=null){
	    var d = new Date();
	    d.setTime( co.signedInfo.timestamp.msec );
	    
	    var bytes = [217, 185, 12, 225, 217, 185, 12, 225];
	    
	    output += "TimeStamp: "+d;
	    output+= "<br />";
	    output += "TimeStamp(number): "+ co.signedInfo.timestamp.msec;
	    
	    output+= "<br />";
	}
	if(co.signedInfo !=null && co.signedInfo.finalBlockID!=null){
	    output += "FinalBlockID: "+ DataUtils.toHex(co.signedInfo.finalBlockID);
	    output+= "<br />";
	}
/*	if(co.signedInfo!=null && co.signedInfo.locator!=null && co.signedInfo.locator.certificate!=null){
	    var certificateHex = DataUtils.toHex(co.signedInfo.locator.certificate).toLowerCase();
	    var signature = DataUtils.toHex(co.signature.signature).toLowerCase();
	    var input = DataUtils.toString(co.rawSignatureData);
	    
	    output += "Hex Certificate: "+ certificateHex ;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    var x509 = new X509();
	    x509.readCertHex(certificateHex);
	    output += "Public key (hex) modulus: " + x509.subjectPublicKeyRSA.n.toString(16) + "<br/>";
	    output += "exponent: " + x509.subjectPublicKeyRSA.e.toString(16) + "<br/>";
	    output += "<br/>";
	    
	    var result = x509.subjectPublicKeyRSA.verifyByteArray(co.rawSignatureData, null, signature);
	    if(LOG>2) console.log('result is '+result);
	    
	    var n = x509.subjectPublicKeyRSA.n;
	    var e =  x509.subjectPublicKeyRSA.e;
	    
	    if(LOG>2) console.log('PUBLIC KEY n after is ');
	    if(LOG>2) console.log(n);

	    if(LOG>2) console.log('EXPONENT e after is ');
	    if(LOG>2) console.log(e);
	    
	    if(result)
            output += 'SIGNATURE VALID';
	    else
            output += 'SIGNATURE INVALID';
	    
	    //output += "VALID: "+ toHex(co.signedInfo.locator.publicKey);
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    //if(LOG>4) console.log('str'[1]);
	}*/
	if(co.signedInfo!=null && co.signedInfo.locator!=null && co.signedInfo.locator.publicKey!=null){
	    var publickeyHex = DataUtils.toHex(co.signedInfo.locator.publicKey).toLowerCase();
	    var publickeyString = DataUtils.toString(co.signedInfo.locator.publicKey);
	    var signature = DataUtils.toHex(co.signature.signature).toLowerCase();
	    var input = DataUtils.toString(co.rawSignatureData);
	    
	    //var wit = null;
	    var witHex = "";
		if (co.signature.Witness != null) {
			//wit = new Witness();
			//wit.decode(co.signature.Witness);
			witHex = DataUtils.toHex(co.signature.Witness);
		}
	    
	    output += "Public key: " + publickeyHex;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    if(LOG>2) console.log(" ContentName + SignedInfo + Content = "+input);
	    if(LOG>2) console.log(" PublicKeyHex = "+publickeyHex );
	    if(LOG>2) console.log(" PublicKeyString = "+publickeyString );
	    
	    if(LOG>2) console.log(" Signature "+signature );
	    if(LOG>2) console.log(" Witness "+witHex );
	    
	    if(LOG>2) console.log(" Signature NOW IS" );
	    
	    if(LOG>2) console.log(co.signature.signature);
	   
	    var rsakey = new Key();
	    rsakey.readDerPublicKey(co.signedInfo.locator.publicKey);

/*	    output += "Public key (hex) modulus: " + rsakey.n.toString(16) + "<br/>";
	    output += "exponent: " + rsakey.e.toString(16) + "<br/>";
	    output += "<br/>";
*/	   	    
	    var result = co.verify(rsakey);
	    // var result = rsakey.verifyString(input, signature);
	    
/*	    if(LOG>2) console.log('PUBLIC KEY n after is ');
	    if(LOG>2) console.log(rsakey.n);

	    if(LOG>2) console.log('EXPONENT e after is ');
	    if(LOG>2) console.log(rsakey.e);
*/	    
	    if(result)
			output += 'SIGNATURE VALID';
	    else
			output += 'SIGNATURE INVALID';
	    
	    //output += "VALID: "+ toHex(co.signedInfo.locator.publicKey);
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    //if(LOG>4) console.log('str'[1]);
	}
    }

    return output;
}

//
// Deprecated: For the browser, define these in the global scope.  Applications should access as member of EncodingUtils.
//

var encodeToHexInterest = function(interest) { return EncodingUtils.encodeToHexInterest(interest); }
var encodeToHexContentObject = function(co) { return EncodingUtils.encodeToHexContentObject(co); }
var encodeForwardingEntry = function(co) { return EncodingUtils.encodeForwardingEntry(co); }
var decodeHexFaceInstance = function(input) { return EncodingUtils.decodeHexFaceInstance(input); }
var decodeHexInterest = function(input) { return EncodingUtils.decodeHexInterest(input); }
var decodeHexContentObject = function(input) { return EncodingUtils.decodeHexContentObject(input); }
var decodeHexForwardingEntry = function(input) { return EncodingUtils.decodeHexForwardingEntry(input); }
var decodeSubjectPublicKeyInfo = function(input) { return EncodingUtils.decodeSubjectPublicKeyInfo(input); }
var contentObjectToHtml = function(co) { return EncodingUtils.contentObjectToHtml(co); }

/**
 * @deprecated Use interest.encode().
 */
function encodeToBinaryInterest(interest) { return interest.encode(); }
/**
 * @deprecated Use contentObject.encode().
 */
function encodeToBinaryContentObject(contentObject) { return contentObject.encode(); }

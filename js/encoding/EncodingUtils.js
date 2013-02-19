/**
 * This file contains utilities to help encode and decode NDN objects.
 * author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 */

function encodeToHexInterest(interest){
    return DataUtils.toHex(encodeToBinaryInterest(interest));
}


function encodeToBinaryInterest(interest) {
	var enc = new BinaryXMLEncoder();
	interest.to_ccnb(enc);
	
	return enc.getReducedOstream();
}


function encodeToHexContentObject(co){
    return DataUtils.toHex(encodeToBinaryContentObject(co));
}

function encodeToBinaryContentObject(co){
	var enc = new BinaryXMLEncoder();
	co.to_ccnb(enc);

	return enc.getReducedOstream();
}

function encodeForwardingEntry(co){
	var enc = new BinaryXMLEncoder();
 
	co.to_ccnb(enc);
	
	var bytes = enc.getReducedOstream();

	return bytes;

	
}



function decodeHexFaceInstance(result){
	
	var numbers = DataUtils.toNumbers(result);
			
	
	var decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODING HEX FACE INSTANCE  \n'+numbers);

	var faceInstance = new FaceInstance();

	faceInstance.from_ccnb(decoder);

	return faceInstance;
	
}



function decodeHexInterest(result){
	var numbers = DataUtils.toNumbers(result);	
	
	var decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODING HEX INTERST  \n'+numbers);

	var interest = new Interest();

	interest.from_ccnb(decoder);

	return interest;
	
}



function decodeHexContentObject(result){
	var numbers = DataUtils.toNumbers(result);
	
	var decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODED HEX CONTENT OBJECT \n'+numbers);
	
	var co = new ContentObject();

	co.from_ccnb(decoder);

	return co;
	
}



function decodeHexForwardingEntry(result){
	var numbers = DataUtils.toNumbers(result);

	var decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODED HEX FORWARDING ENTRY \n'+numbers);
	
	var forwardingEntry = new ForwardingEntry();

	forwardingEntry.from_ccnb(decoder);

	return forwardingEntry;
	
}

/*
 * Decode the Uint8Array which holds SubjectPublicKeyInfo and return an RSAKey.
 */
function decodeSubjectPublicKeyInfo(array) {
    var hex = DataUtils.toHex(array).toLowerCase();
    var a = _x509_getPublicKeyHexArrayFromCertHex(hex, _x509_getSubjectPublicKeyPosFromCertHex(hex, 0));
    var rsaKey = new RSAKey();
    rsaKey.setPublic(a[0], a[1]);
    return rsaKey;
}

/* Return a user friendly HTML string with the contents of co.
   This also outputs to console.log.
 */
function contentObjectToHtml(/* ContentObject */ co) {
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
	if(co.signature !=null && co.signature.signature!=null){
	    output += "SIGNATURE(hex): "+ DataUtils.toHex(co.signature.signature);
	    
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
	if(co.signedInfo!=null && co.signedInfo.locator!=null && co.signedInfo.locator.certificate!=null){
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
	}
	if(co.signedInfo!=null && co.signedInfo.locator!=null && co.signedInfo.locator.publicKey!=null){
	    var publickeyHex = DataUtils.toHex(co.signedInfo.locator.publicKey).toLowerCase();
	    var publickeyString = DataUtils.toString(co.signedInfo.locator.publicKey);
	    var signature = DataUtils.toHex(co.signature.signature).toLowerCase();
	    var input = DataUtils.toString(co.rawSignatureData);
	    
	    var wit = null;
	    var witHex = "";
		if (co.signature.Witness != null) {
			wit = new Witness();
			wit.decode(co.signature.Witness);
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
	   
	    var rsakey = decodeSubjectPublicKeyInfo(co.signedInfo.locator.publicKey);

	    output += "Public key (hex) modulus: " + rsakey.n.toString(16) + "<br/>";
	    output += "exponent: " + rsakey.e.toString(16) + "<br/>";
	    output += "<br/>";
	   	    
	    var result = rsakey.verifyByteArray(co.rawSignatureData, wit, signature);
	    // var result = rsakey.verifyString(input, signature);
	    
	    if(LOG>2) console.log('PUBLIC KEY n after is ');
	    if(LOG>2) console.log(rsakey.n);

	    if(LOG>2) console.log('EXPONENT e after is ');
	    if(LOG>2) console.log(rsakey.e);
	    
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



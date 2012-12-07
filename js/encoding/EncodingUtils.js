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
			
	
	decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODING HEX FACE INSTANCE  \n'+numbers);

	var faceInstance = new FaceInstance();

	faceInstance.from_ccnb(decoder);

	return faceInstance;
	
}



function decodeHexInterest(result){
	var numbers = DataUtils.toNumbers(result);	
	
	decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODING HEX INTERST  \n'+numbers);

	var interest = new Interest();

	interest.from_ccnb(decoder);

	return interest;
	
}



function decodeHexContentObject(result){
	var numbers = DataUtils.toNumbers(result);
	
	decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODED HEX CONTENT OBJECT \n'+numbers);
	
	co = new ContentObject();

	co.from_ccnb(decoder);

	return co;
	
}



function decodeHexForwardingEntry(result){
	var numbers = DataUtils.toNumbers(result);

	decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODED HEX FORWARDING ENTRY \n'+numbers);
	
	forwardingEntry = new ForwardingEntry();

	forwardingEntry.from_ccnb(decoder);

	return forwardingEntry;
	
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
	    var tmp = DataUtils.toString(co.signedInfo.locator.certificate);
	    var publickey = rstr2b64(tmp);
	    var publickeyHex = DataUtils.toHex(co.signedInfo.locator.certificate).toLowerCase();
	    var publickeyString = DataUtils.toString(co.signedInfo.locator.certificate);
	    var signature = DataUtils.toHex(co.signature.signature).toLowerCase();
	    var input = DataUtils.toString(co.rawSignatureData);
	    
	    output += "DER Certificate: "+publickey ;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    if(LOG>2) console.log(" ContentName + SignedInfo + Content = "+input);
	    
	    if(LOG>2) console.log("HEX OF ContentName + SignedInfo + Content = ");
	    if(LOG>2) console.log(DataUtils.stringtoBase64(input));
	    
	    if(LOG>2) console.log(" PublicKey = "+publickey );
	    if(LOG>2) console.log(" PublicKeyHex = "+publickeyHex );
	    if(LOG>2) console.log(" PublicKeyString = "+publickeyString );
	    
	    if(LOG>2) console.log(" Signature is");
	    if(LOG>2) console.log( signature );
	    //if(LOG>2) console.log(" Signature NOW IS" );
	    //if(LOG>2) console.log(co.signature.signature);

	    var x509 = new X509();
	    x509.readCertPEM(publickey);
	    
	    //x509.readCertPEMWithoutRSAInit(publickey);

	    var result = x509.subjectPublicKeyRSA.verifyByteArray(co.rawSignatureData, signature);
	    if(LOG>2) console.log('result is '+result);
	    
	    var n = x509.subjectPublicKeyRSA.n;
	    var e =  x509.subjectPublicKeyRSA.e;
	    
	    if(LOG>2) console.log('PUBLIC KEY n after is ');
	    if(LOG>2) console.log(n);

	    if(LOG>2) console.log('EXPONENT e after is ');
	    if(LOG>2) console.log(e);
	    
	    /*var rsakey = new RSAKey();
	      
	      var kp = publickeyHex.slice(56,314);
	      
	      output += "PUBLISHER KEY(hex): "+kp ;
	      
	      output+= "<br />";
	      output+= "<br />";
	      
	      console.log('kp is '+kp);
	      
	      var exp = publickeyHex.slice(318,324);
	      
	      console.log('kp size is '+kp.length );
	      output += "exponent: "+exp ;
	      
	      output+= "<br />";
	      output+= "<br />";
	      
	      console.log('exp is '+exp);
	      
	      rsakey.setPublic(kp,exp);

	      var result = rsakey.verifyString(input, signature);*/
	    
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
	    var publickey = rstr2b64(DataUtils.toString(co.signedInfo.locator.publicKey));
	    var publickeyHex = DataUtils.toHex(co.signedInfo.locator.publicKey).toLowerCase();
	    var publickeyString = DataUtils.toString(co.signedInfo.locator.publicKey);
	    var signature = DataUtils.toHex(co.signature.signature).toLowerCase();
	    var input = DataUtils.toString(co.rawSignatureData);
	    
	    output += "DER Certificate: "+publickey ;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    if(LOG>2) console.log(" ContentName + SignedInfo + Content = "+input);
	    if(LOG>2) console.log(" PublicKey = "+publickey );
	    if(LOG>2) console.log(" PublicKeyHex = "+publickeyHex );
	    if(LOG>2) console.log(" PublicKeyString = "+publickeyString );
	    
	    if(LOG>2) console.log(" Signature "+signature );
	    
	    if(LOG>2) console.log(" Signature NOW IS" );
	    
	    if(LOG>2) console.log(co.signature.signature);
	    
	    /*var x509 = new X509();
	      
	      x509.readCertPEM(publickey);
	      
	      
	      //x509.readCertPEMWithoutRSAInit(publickey);

	      var result = x509.subjectPublicKeyRSA.verifyString(input, signature);*/
	    //console.log('result is '+result);
	    
	    var kp = publickeyHex.slice(56,314);
	    
	    output += "PUBLISHER KEY(hex): "+kp ;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    if(LOG>2) console.log('PUBLIC KEY IN HEX is ');
	    if(LOG>2) console.log(kp);

	    var exp = publickeyHex.slice(318,324);
	    
	    if(LOG>2) console.log('kp size is '+kp.length );
	    output += "exponent: "+exp ;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    if(LOG>2) console.log('EXPONENT is ');
	    if(LOG>2) console.log(exp);
	    
	    /*var c1 = hex_sha256(input);
	      var c2 = signature;
	      
	      if(LOG>4)console.log('input is ');
	      if(LOG>4)console.log(input);
	      if(LOG>4)console.log('C1 is ');
	      if(LOG>4)console.log(c1);
	      if(LOG>4)console.log('C2 is ');
	      if(LOG>4)console.log(c2);
	      var result = c1 == c2;*/
	    
	    var rsakey = new RSAKey();
	    
	    rsakey.setPublic(kp,exp);
	    
	    var result = rsakey.verifyByteArray(co.rawSignatureData,signature);
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

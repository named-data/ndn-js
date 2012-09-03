



function encodeToHexInterest(int){
	
	var enc = new BinaryXMLEncoder();
 
	int.encode(enc);
	
	var hex = DataUtils.toHex(enc.getReducedOstream());

	return hex;

	
}


function encodeToHexContentObject(co){
	var enc = new BinaryXMLEncoder();
 
	co.encode(enc);
	
	var hex = DataUtils.toHex(enc.getReducedOstream());

	return hex;

	
}

function encodeToBinaryContentObject(co){
	var enc = new BinaryXMLEncoder();
 
	co.encode(enc);
	
	var hex = enc.getReducedOstream();

	return hex;

	
}

function encodeForwardingEntry(co){
	var enc = new BinaryXMLEncoder();
 
	co.encode(enc);
	
	var bytes = enc.getReducedOstream();

	return bytes;

	
}



function decodeHexFaceInstance(result){
	
	var numbers = DataUtils.toNumbers(result);
			
	
	decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODING HEX FACE INSTANCE  \n'+numbers);

	i = new FaceInstance();

	i.decode(decoder);

	return i;
	
}

function decodeHexInterest(result){
	var numbers = DataUtils.toNumbers(result);
			
	
	decoder = new BinaryXMLDecoder(numbers);
	if(LOG>3)console.log('DECODING HEX INTERST  \n'+numbers);

	i = new Interest();

	i.decode(decoder);

	return i;
	
}



function decodeHexContentObject(result){
	var numbers = DataUtils.toNumbers(result);

	decoder = new BinaryXMLDecoder(numbers);
	if(LOG>3)console.log('DECODED HEX CONTENT OBJECT \n'+numbers);
	
	co = new ContentObject();

	co.decode(decoder);

	return co;
	
}



function decodeHexForwardingEntry(result){
	var numbers = DataUtils.toNumbers(result);

	decoder = new BinaryXMLDecoder(numbers);
	
	if(LOG>3)console.log('DECODED HEX FORWARDING ENTRY \n'+numbers);
	
	co = new ForwardingEntry();

	co.decode(decoder);

	return co;
	
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
	if(co.Name!=null && co.Name.Components!=null){
	    output+= "NAME: ";
	    
	    for(var i=0;i<co.Name.Components.length;i++){
		output+= "/"+ DataUtils.toString(co.Name.Components[i]);
	    }
	    output+= "<br />";
	    output+= "<br />";
	}
	
	if(co.Content !=null){
	    output += "CONTENT(ASCII): "+ DataUtils.toString(co.Content);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.Content !=null){
	    output += "CONTENT(hex): "+ DataUtils.toHex(co.Content);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.Signature !=null && co.Signature.Signature!=null){
	    output += "SIGNATURE(hex): "+ DataUtils.toHex(co.Signature.Signature);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.SignedInfo !=null && co.SignedInfo.Publisher!=null && co.SignedInfo.Publisher.PublisherPublicKeyDigest!=null){
	    output += "Publisher Public Key Digest(hex): "+ DataUtils.toHex(co.SignedInfo.Publisher.PublisherPublicKeyDigest);
	    
	    output+= "<br />";
	    output+= "<br />";
	}
	if(co.SignedInfo !=null && co.SignedInfo.Timestamp!=null){
	    var d = new Date();
	    d.setTime( co.SignedInfo.Timestamp.msec );
	    
	    var bytes = [217, 185, 12, 225, 217, 185, 12, 225];
	    
	    output += "TimeStamp: "+d;
	    output+= "<br />";
	    output += "TimeStamp(number): "+ co.SignedInfo.Timestamp.msec;
	    
	    output+= "<br />";
	}
	if(co.SignedInfo!=null && co.SignedInfo.Locator!=null && co.SignedInfo.Locator.Certificate!=null){
	    var tmp = DataUtils.toString(co.SignedInfo.Locator.Certificate);
	    var publickey = rstr2b64(tmp);
	    var publickeyHex = DataUtils.toHex(co.SignedInfo.Locator.Certificate).toLowerCase();
	    var publickeyString = DataUtils.toString(co.SignedInfo.Locator.Certificate);
	    var signature = DataUtils.toHex(co.Signature.Signature).toLowerCase();
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
	    //if(LOG>2) console.log(co.Signature.Signature);

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
	    
	    //output += "VALID: "+ toHex(co.SignedInfo.Locator.PublicKey);
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    //if(LOG>4) console.log('str'[1]);
	}
	if(co.SignedInfo!=null && co.SignedInfo.Locator!=null && co.SignedInfo.Locator.PublicKey!=null){
	    var publickey = rstr2b64(DataUtils.toString(co.SignedInfo.Locator.PublicKey));
	    var publickeyHex = DataUtils.toHex(co.SignedInfo.Locator.PublicKey).toLowerCase();
	    var publickeyString = DataUtils.toString(co.SignedInfo.Locator.PublicKey);
	    var signature = DataUtils.toHex(co.Signature.Signature).toLowerCase();
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
	    
	    if(LOG>2) console.log(co.Signature.Signature);
	    
	    /*var x509 = new X509();
	      
	      x509.readCertPEM(publickey);
	      
	      
	      //x509.readCertPEMWithoutRSAInit(publickey);

	      var result = x509.subjectPublicKeyRSA.verifyString(input, signature);*/
	    //console.log('result is '+result);
	    
	    var kp = publickeyHex.slice(56,314);
	    
	    output += "PUBLISHER KEY(hex): "+kp ;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    console.log('PUBLIC KEY IN HEX is ');
	    console.log(kp);

	    var exp = publickeyHex.slice(318,324);
	    
	    console.log('kp size is '+kp.length );
	    output += "exponent: "+exp ;
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    console.log('EXPONENT is ');
	    console.log(exp);
	    
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
	    
	    console.log('PUBLIC KEY n after is ');
	    console.log(rsakey.n);

	    console.log('EXPONENT e after is ');
	    console.log(rsakey.e);
	    
	    if(result)
		output += 'SIGNATURE VALID';
	    else
		output += 'SIGNATURE INVALID';
	    
	    //output += "VALID: "+ toHex(co.SignedInfo.Locator.PublicKey);
	    
	    output+= "<br />";
	    output+= "<br />";
	    
	    //if(LOG>4) console.log('str'[1]);
	}
    }

    return output;
}





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
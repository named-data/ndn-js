
var BinaryXMLEncoder = function BinaryXMLEncoder(){
	
BinaryXMLEncoder.prototype.writeStartElement = function(
		//String 
		tag, 
		//TreeMap<String,String> 
		attributes){
	
}
	try {
		var dictionaryVal = stringToTag(tag);
		
		if (null == dictionaryVal) {
			BinaryXMLCodec.encodeUString(_ostream, tag, BinaryXMLCodec.XML_TAG);
			
		} else {
			BinaryXMLCodec.encodeTypeAndVal(BinaryXMLCodec.XML_DTAG, dictionaryVal, _ostream);
		}
		
		if (null != attributes) {
			writeAttributes(attributes); 
		}
		
	} catch (e) {
		throw new Exception(e);
	}
};


//TODO
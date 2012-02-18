var MARK_LEN=512;
var DEBUG_MAX_LEN =  32768;

var BinaryXMLDecoder = new BinaryXMLDecoder(_Istream){
	this.Istream = _Istream;
	
};


BinaryXMLDecoder.prototype.readStartElement =function(
	//String
	startTag,				    
	//TreeMap<String, String>
	attributes) {

	try {
		BinaryXMLCodec.TypeAndVal tv = BinaryXMLCodec.decodeTypeAndVal(this.Istream);
		
		if (null == tv) {
			throw new Exception("Expected start element: " + startTag + " got something not a tag.");
		}
		
		String decodedTag = null;
		
		if (tv.type() == BinaryXMLCodec.XML_TAG) {
			
			decodedTag = BinaryXMLCodec.decodeUString(this.Istream, tv.val()+1);
			
		} else if (tv.type() == BinaryXMLCodec.XML_DTAG) {
			decodedTag = tagToString(tv.val());	
		}
		
		if ((null ==  decodedTag) || (!decodedTag.equals(startTag))) {
			throw new Exception("Expected start element: " + startTag + " got: " + decodedTag + "(" + tv.val() + ")");
		}
		
		if (null != attributes) {
			readAttributes(attributes); 
		}
		
	} catch (e) {
		throw new Exception("readStartElement", e);
	}
};

BinaryXMLDecoder.prototype.readAttributes = function(
	//TreeMap<String,String> 
	attributes){
	
	if (null == attributes) {
		return;
	}

	try {

		BinaryXMLCodec.TypeAndVal nextTV = BinaryXMLCodec.peekTypeAndVal(_istream);

		while ((null != nextTV) && ((BinaryXMLCodec.XML_ATTR == nextTV.type()) ||
				(BinaryXMLCodec.XML_DATTR == nextTV.type()))) {

			BinaryXMLCodec.TypeAndVal thisTV = BinaryXMLCodec.decodeTypeAndVal(this.Istream);

			var attributeName = null;
			if (BinaryXMLCodec.XML_ATTR == thisTV.type()) {
				
				attributeName = BinaryXMLCodec.decodeUString(_istream, thisTV.val()+1);

			} else if (BinaryXMLCodec.XML_DATTR == thisTV.type()) {
				// DKS TODO are attributes same or different dictionary?
				attributeName = tagToString(thisTV.val());
				if (null == attributeName) {
					throw new ContentDecodingException("Unknown DATTR value" + thisTV.val());
				}
			}
			
			var attributeValue = BinaryXMLCodec.decodeUString(_istream);

			attributes.put(attributeName, attributeValue);

			nextTV = BinaryXMLCodec.peekTypeAndVal(_istream);
		}

	} catch ( e) {

		throw new ContentDecodingException("readStartElement", e);
	}
};

//TODO
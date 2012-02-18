
var CCNProtocolDTags = require('./CCNProtocolDTags').CCNProtocolDTags;

var Exclude = function Exclude(_Values){ 
	
	this.OPTIMUM_FILTER_SIZE = 100;
	

	this.Values = _Values; //array of elements
	
}
exports.Exclude = Exclude;

Exclude.prototype.decode = function(/*XMLDecoder*/ decoder) {


		
		decoder.readStartElement(this.getElementLabel());

			//TODO BUGS
			/*var component;
			var any = false;
			while ((component = decoder.peekStartElement(CCNProtocolDTags.Component)) || 
					(any = decoder.peekStartElement(CCNProtocolDTags.Any)) ||
						decoder.peekStartElement(CCNProtocolDTags.Bloom)) {
				var ee = component?new ExcludeComponent(): any ? new ExcludeAny() : new BloomFilter();
				ee.decode(decoder);
				_values.add(ee);
			}*/

			decoder.readEndElement();

};

Exclude.prototype.encode=function(/*XMLEncoder*/ encoder)  {
		if (!validate()) {
			throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
		}
		// if everything is null, output nothing
		if (empty())
			return;
		
		encoder.writeStartElement(getElementLabel());

		/*
		for (Element element : _values)
			element.encode(encoder);
		*/

		encoder.writeEndElement();
	};

Exclude.prototype.getElementLabel = function() { return CCNProtocolDTags.Exclude; };


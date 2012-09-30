/*
 * @author: ucla-cs
 * This class represents Exclude objects
 */

var Exclude = function Exclude(_values){ 
	
	this.OPTIMUM_FILTER_SIZE = 100;
	

	this.values = _values; //array of elements
	
}

Exclude.prototype.from_ccnb = function(/*XMLDecoder*/ decoder) {


		
		decoder.readStartElement(this.getElementLabel());

		//TODO APPLY FILTERS/EXCLUDE
		
		//TODO 
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

Exclude.prototype.to_ccnb=function(/*XMLEncoder*/ encoder)  {
		if (!validate()) {
			throw new ContentEncodingException("Cannot encode " + this.getClass().getName() + ": field values missing.");
		}

		if (empty())
			return;

		encoder.writeStartElement(getElementLabel());

		encoder.writeEndElement();
		
	};

Exclude.prototype.getElementLabel = function() { return CCNProtocolDTags.Exclude; };


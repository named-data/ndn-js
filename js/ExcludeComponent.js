/*
 * @author: ucla-cs
 * This class represents Exclude Component OBjects
 */

var ExcludeComponent = function ExcludeComponent(_body) {

	//TODO Check BODY is an Array of componenets.
	
	this.body = _body
};

ExcludeComponent.prototype.from_ccnb = function( decoder)  {
		this.body = decoder.readBinaryElement(this.getElementLabel());
};

ExcludeComponent.prototype.to_ccnb = function(encoder) {
		encoder.writeElement(this.getElementLabel(), this.body);
};

ExcludeComponent.prototype.getElementLabel = function() { return CCNProtocolDTags.Component; };


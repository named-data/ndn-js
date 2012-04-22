/*
 * @author: ucla-cs
 * This class represents Exclude Component OBjects
 */

var ExcludeComponent = function ExcludeComponent(_Body) {

	//TODO Check BODY is an Array of componenets.
	
	this.Body = _Body
};

ExcludeComponent.prototype.decode = function( decoder)  {
		body = decoder.readBinaryElement(this.getElementLabel());
};

ExcludeComponent.prototype.encode = function(encoder) {
		encoder.writeElement(this.getElementLabel(), body);
};

ExcludeComponent.prototype.getElementLabel = function() { return CCNProtocolDTags.Component; };


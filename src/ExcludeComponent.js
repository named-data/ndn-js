var CCNProtocolDTags = require('./CCNProtocolDTags').CCNProtocolDTags;

/*
 * _Body is an array of componenets
 */
var ExcludeComponent = function ExcludeComponent(_Body) {

	//TODO Check BODY is an Array of componenets.
	
	this.Body = _Body
};
exports.ExcludeComponent = ExcludeComponent;

ExcludeComponent.prototype.decode = function( decoder)  {
		body = decoder.readBinaryElement(this.getElementLabel());
};

ExcludeComponent.prototype.encode = function(encoder) {
		encoder.writeElement(this.getElementLabel(), body);
};

ExcludeComponent.prototype.getElementLabel = function() { return CCNProtocolDTags.Component; };


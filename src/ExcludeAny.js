
var CCNProtocolDTags = require('./CCNProtocolDTags').CCNProtocolDTags;

var ExcludeAny = function ExcludeAny() {

};

exports.ExcludeAny= ExcludeAny;

ExcludeAny.prototype.decode = function(decoder) {
		decoder.readStartElement(this.getElementLabel());
		decoder.readEndElement();
};


ExcludeAny.prototype.encode = function( encoder) {
		encoder.writeStartElement(this.getElementLabel());
		encoder.writeEndElement();
};

ExcludeAny.prototype.getElementLabel=function() { return CCNProtocolDTags.Any; };

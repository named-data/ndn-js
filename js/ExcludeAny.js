/*
 * @author: ucla-cs
 * This class represents ExcludeAny objects
 */

var ExcludeAny = function ExcludeAny() {

};

ExcludeAny.prototype.from_ccnb = function(decoder) {
		decoder.readStartElement(this.getElementLabel());
		decoder.readEndElement();
};


ExcludeAny.prototype.to_ccnb = function( encoder) {
		encoder.writeStartElement(this.getElementLabel());
		encoder.writeEndElement();
};

ExcludeAny.prototype.getElementLabel=function() { return CCNProtocolDTags.Any; };

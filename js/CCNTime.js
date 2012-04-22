/*
 * @author: ucla-cs
 * This class represents CCNTime Objects
 */

var CCNTime = function CCNTime(
                               //long 
msec) {




	this.NANOS_MAX = 999877929;
	
	this.date = new Date(msec);
};


	/**
	 * Create a CCNTime
	 * @param timestamp source timestamp to initialize from, some precision will be lost
	 */

	/**
	 * Create a CCNTime
	 * @param time source Date to initialize from, some precision will be lost
	 * as CCNTime does not round to unitary milliseconds
	 */
CCNTime.prototype.setDate = function(
	//Date 
		date) {

	this.date = date;
};
	
	/**
	 * Create a CCNTime from its binary encoding
	 * @param binaryTime12 the binary representation of a CCNTime
	 */
CCNTime.prototype.setDateBinary = function(
	//byte [] 
		binaryTime12) {


	if ((null == binaryTime12) || (binaryTime12.length == 0)) {
		throw new IllegalArgumentException("Invalid binary time!");
	}
	

	value = 0;
	for(i = 0; i < binaryTime12.length; i++) {
		value = value << 8;
		// Java will assume the byte is signed, so extend it and trim it.
		b = (binaryTime12[i]) & 0xFF;
		value |= b;
	}
	
	this.date = new Date(value);

};

//byte[]
CCNTime.prototype.toBinaryTime = function() {
	
	

	return unsignedLongToByteArray(this.date.getTime());

}

unsignedLongToByteArray= function( value) {
	if( 0 == value )
		return [0];

	if( 0 <= value && value <= 0x00FF ) {
		//byte [] 
		bb = new Array[1];
		bb[0] = (value & 0x00FF);
		return bb;
	}

	
	//byte [] 
	out = null;
	//int
	offset = -1;
	for(var i = 7; i >=0; --i) {
		//byte
		b = ((value >> (i * 8)) & 0xFF);
		if( out == null && b != 0 ) {
			out = new Array(i+1);//byte[i+1];
			offset = i;
		}
		if( out != null )
			out[ offset - i ] = b;
	}
	return out;
}
	

/*
 * @author: ucla-cs
 * This class represents CCNTime Objects
 */

var CCNTime = function CCNTime(
                               
		msec) {




	this.NANOS_MAX = 999877929;
	
	if(typeof msec =='object'){
		this.setDateBinary(msec);
		this.msec = msec;
		this.msecHex = toHex(msec);
	}
	else if(typeof msec =='string'){
		
		this.msec = toNumbers(msec);
		this.setDateBinary(this.msec);
		this.msecHex = msec;
	}
	else{
		if(LOG>1) console.log('UNRECOGNIZED TYPE FOR TIME');
	}
};


	/**
	 * Create a CCNTime
	 * @param timestamp source timestamp to initialize from, some precision will be lost
	 */


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
		b = (binaryTime12[i]) & 0xFF;
		value |= b;
	}
	
	this.date = value;
	//this.date = new Date(value);

};

//byte[]
CCNTime.prototype.toBinaryTime = function() {

	return this.msec; //unsignedLongToByteArray(this.date.getTime());

}
/*
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
}*/
	

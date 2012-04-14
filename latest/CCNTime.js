
var CCNTime = function CCNTime(
                               //long 
msec) {



	//byte [] 
	//this.binarytime = null;
	

	this.NANOS_MAX = 999877929;
	
	this.date = new Date(msec);
};


//public CCNTime(long msec) {
	//this((msec/1000) * 1000, (msec % 1000) * 1000000L);
//}

	/**
	 * Create a CCNTime
	 * @param timestamp source timestamp to initialize from, some precision will be lost
	 */
	//public CCNTime(Timestamp timestamp) {
		//this(timestamp.getTime(), timestamp.getNanos());
	//}
	
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
	
/**
 * Generate the binary representation of a CCNTime
 * @return the binary representation we use for encoding
 */
//byte [] 
/*CCCCNTime.prototype.toBinaryTime = function() {

		if( null == _binarytime ) {
			byte [] b = DataUtils.unsignedLongToByteArray(toBinaryTimeAsLong());
			_binarytime = b;
		}
		return _binarytime;
};*/
	
	/**
	 * Generate the internal long representation of a CCNTime, useful for comparisons
	 * and used internally
	 * @return the long representation of this time in our internal units
	 */
	//public long toBinaryTimeAsLong() {
		//return toBinaryTimeAsLong(getTime(), getNanos());
	//}
	
	/**
	 * Static method to convert from milliseconds and nanoseconds to our
	 * internal long representation.
	 * Assumes that nanos also contains the integral milliseconds for this
	 * time. Ignores msec component in msec.
	 * @param msec milliseconds
	 * @param nanos nanoseconds
	 * @return
	 */
	//public static long toBinaryTimeAsLong(long msec, long nanos) {
		//long timeVal = (msec / 1000) * 4096L + (nanos * 4096L + 500000000L) / 1000000000L;
		//return timeVal;		
	//}
	
	/*protected void setFromBinaryTimeAsLong(long binaryTimeAsLong) {
		_binarytime = null;
		super.setTime((binaryTimeAsLong / 4096L) * 1000L);
		super.setNanos((int)(((binaryTimeAsLong % 4096L) * 1000000000L) / 4096L));
	}*/
	
	/*@Override
	public void setTime(long msec) {
		_binarytime = null;
		long binaryTimeAsLong = toBinaryTimeAsLong((msec/1000) * 1000, (msec % 1000) * 1000000L);
		super.setTime((binaryTimeAsLong / 4096L) * 1000L);
		super.setNanos((int)(((binaryTimeAsLong % 4096L) * 1000000000L) / 4096L));
	}*/

	/*@Override
	public void setNanos(int nanos) {
		_binarytime = null;
		int quantizedNanos = (int)(((((nanos * 4096L + 500000000L) / 1000000000L)) * 1000000000L) / 4096L);
		if ((quantizedNanos < 0) || (quantizedNanos > 999999999)) {
			System.out.println("Quantizing nanos " + nanos + " resulted in out of range value " + quantizedNanos + "!");
		}
	   	super.setNanos(quantizedNanos);
	}*/

	/*public void addNanos(int nanos) {
		_binarytime = null;
		setNanos(nanos + getNanos());
	}*/
	
	/*
	public void increment(int timeUnits) {
		_binarytime = null;
		long binaryTimeAsLong = toBinaryTimeAsLong();
		binaryTimeAsLong += timeUnits;
		setFromBinaryTimeAsLong(binaryTimeAsLong);
	}

	@Override
	public boolean equals(Timestamp ts) {
		return super.equals(new CCNTime(ts));
	}

	@Override
	public int compareTo(Date o) {
		return super.compareTo(new CCNTime(o));
	}

	@Override
	public int compareTo(Timestamp ts) {
		return super.compareTo(new CCNTime(ts));
	}

	@Override
	public boolean before(Timestamp ts) {
		return super.before(new CCNTime(ts));
	}

	@Override
	public boolean after(Timestamp ts) {
		return super.after(new CCNTime(ts));
	}

	@Override
	public boolean before(Date when) {
		return super.before(new CCNTime(when));
	}
	
	@Override
	public boolean after(Date when) {
		return super.after(new CCNTime(when));
	}


	public static CCNTime now() {
		return new CCNTime();
	}
	

	public String toShortString() {
		// use . instead of : as URI printer will make it look nicer in the logs
		SimpleDateFormat df = new SimpleDateFormat("yy-MM-dd-HH.mm.ss");
		return df.format(this);
	}
}*/

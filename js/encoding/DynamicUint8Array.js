/**
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 * Encapsulate an Uint8Array and support dynamic reallocation.
 */

/*
 * Create a DynamicUint8Array where this.array is a Uint8Array of size length.
 * If length is not supplied, use a default initial length.
 * The methods will update this.length.
 * To access the array, use this.array or call subarray.
 */
var DynamicUint8Array = function DynamicUint8Array(length) {
	if (!length)
        length = 16;
    
    this.array = new Uint8Array(length);
    this.length = length;
};

/*
 * Ensure that this.array has the length, reallocate and copy if necessary.
 * Update this.length which may be greater than length.
 */
DynamicUint8Array.prototype.ensureLength = function(length) {
    if (this.array.length >= length)
        return;
    
    // See if double is enough.
    var newLength = this.array.length * 2;
    if (length > newLength)
        // The needed length is much greater, so use it.
        newLength = length;
    
    var newArray = new Uint8Array(newLength);
    newArray.set(this.array);
    this.array = newArray;
    this.length = newLength;
};

/*
 * Call this.array.set(value, offset), reallocating if necessary. 
 */
DynamicUint8Array.prototype.set = function(value, offset) {
    this.ensureLength(value.length + offset);
    this.array.set(value, offset);
};

/*
 * Return this.array.subarray(begin, end);
 */
DynamicUint8Array.prototype.subarray = function(begin, end) {
    return this.array.subarray(begin, end);
}

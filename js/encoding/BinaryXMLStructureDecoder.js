/**
 * This class uses BinaryXMLDecoder to follow the structure of a ccnb binary element to 
 * determine its end.
 * 
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 */

var BinaryXMLStructureDecoder = function BinaryXMLDecoder() {
    this.gotElementEnd = false;
	this.offset = 0;
    this.level = 0;
    this.state = BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE;
    this.headerLength = 0;
    this.useHeaderBuffer = false;
    this.headerBuffer = new DynamicUint8Array(5);
    this.nBytesToRead = 0;
};

BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE = 0;
BinaryXMLStructureDecoder.READ_BYTES = 1;

/*
 * Continue scanning input starting from this.offset.  If found the end of the element
 *   which started at offset 0 then return true, else false.
 * If this returns false, you should read more into input and call again.
 * You have to pass in input each time because the array could be reallocated.
 * This throws an exception for badly formed ccnb.
 */
BinaryXMLStructureDecoder.prototype.findElementEnd = function(
    // Uint8Array
    input)
{
    if (this.gotElementEnd)
        // Someone is calling when we already got the end.
        return true;
    
    var decoder = new BinaryXMLDecoder(input);
    
    while (true) {
        if (this.offset >= input.length)
            // All the cases assume we have some input.
            return false;
        
        switch (this.state) {
            case BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE:               
                // First check for XML_CLOSE.
                if (this.headerLength == 0 && input[this.offset] == XML_CLOSE) {
                    ++this.offset;
                    // Close the level.
                    --this.level;
                    if (this.level == 0)
                        // Finished.
                        return true;
                    if (this.level < 0)
                        throw new Error("BinaryXMLStructureDecoder: Unexepected close tag at offset " +
                            (this.offset - 1));
                    
                    // Get ready for the next header.
                    this.startHeader();
                    break;
                }
                
                var startingHeaderLength = this.headerLength;
                while (true) {
                    if (this.offset >= input.length) {
                        // We can't get all of the header bytes from this input. Save in headerBuffer.
                        this.useHeaderBuffer = true;
                        var nNewBytes = this.headerLength - startingHeaderLength;
                        this.headerBuffer.set
                            (input.subarray(this.offset - nNewBytes, nNewBytes), startingHeaderLength);
                        
                        return false;
                    }
                    var headerByte = input[this.offset++];
                    ++this.headerLength;
                    if (headerByte & XML_TT_NO_MORE)
                        // Break and read the header.
                        break;
                }
                
                var typeAndVal;
                if (this.useHeaderBuffer) {
                    // Copy the remaining bytes into headerBuffer.
                    nNewBytes = this.headerLength - startingHeaderLength;
                    this.headerBuffer.set
                        (input.subarray(this.offset - nNewBytes, nNewBytes), startingHeaderLength);

                    typeAndVal = new BinaryXMLDecoder(this.headerBuffer.array).decodeTypeAndVal();
                }
                else {
                    // We didn't have to use the headerBuffer.
                    decoder.seek(this.offset - this.headerLength);
                    typeAndVal = decoder.decodeTypeAndVal();
                }
                
                if (typeAndVal == null)
                    throw new Error("BinaryXMLStructureDecoder: Can't read header starting at offset " +
                        (this.offset - this.headerLength));
                
                // Set the next state based on the type.
                var type = typeAndVal.t;
                if (type == XML_DATTR)
                    // We already consumed the item. READ_HEADER_OR_CLOSE again.
                    // ccnb has rules about what must follow an attribute, but we are just scanning.
                    this.startHeader();
                else if (type == XML_DTAG || type == XML_EXT) {
                    // Start a new level and READ_HEADER_OR_CLOSE again.
                    ++this.level;
                    this.startHeader();
                }
                else if (type == XML_TAG || type == XML_ATTR) {
                    if (type == XML_TAG)
                        // Start a new level and read the tag.
                        ++this.level;
                    // Minimum tag or attribute length is 1.
                    this.nBytesToRead = typeAndVal.v + 1;
                    this.state = BinaryXMLStructureDecoder.READ_BYTES;
                    // ccnb has rules about what must follow an attribute, but we are just scanning.
                }
                else if (type == XML_BLOB || type == XML_UDATA) {
                    this.nBytesToRead = typeAndVal.v;
                    this.state = BinaryXMLStructureDecoder.READ_BYTES;
                }
                else
                    throw new Error("BinaryXMLStructureDecoder: Unrecognized header type " + type);
                break;
            
            case BinaryXMLStructureDecoder.READ_BYTES:
                var nRemainingBytes = input.length - this.offset;
                if (nRemainingBytes < this.nBytesToRead) {
                    // Need more.
                    this.offset += nRemainingBytes;
                    this.nBytesToRead -= nRemainingBytes;
                    return false;
                }
                // Got the bytes.  Read a new header or close.
                this.offset += this.nBytesToRead;
                this.startHeader();
                break;
            
            default:
                // We don't expect this to happen.
                throw new Error("BinaryXMLStructureDecoder: Unrecognized state " + this.state);
        }
    }
};

/*
 * Set the state to READ_HEADER_OR_CLOSE and set up to start reading the header
 */
BinaryXMLStructureDecoder.prototype.startHeader = function() {
    this.headerLength = 0;
    this.useHeaderBuffer = false;
    this.state = BinaryXMLStructureDecoder.READ_HEADER_OR_CLOSE;    
}

/*
 *  Set the offset into the input, used for the next read.
 */
BinaryXMLStructureDecoder.prototype.seek = function(
        //int
        offset) {
    this.offset = offset;
}

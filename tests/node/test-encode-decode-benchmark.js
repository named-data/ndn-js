var TestEncodeDecodeBenchmark = require("../browser/test-encode-decode-benchmark.js").TestEncodeDecodeBenchmark;
var WireFormat = require('../..').WireFormat;
var BinaryXmlWireFormat = require('../..').BinaryXmlWireFormat;
var TlvWireFormat = require('../..').TlvWireFormat;

/**
 * Call benchmarkEncodeDataSeconds and benchmarkDecodeDataSeconds with appropriate nInterations.  Print the 
 * results to console.log.
 * @param {boolean} useComplex See benchmarkEncodeDataSeconds.
 * @param {boolean} useCrypto See benchmarkEncodeDataSeconds and benchmarkDecodeDataSeconds.
 */
function benchmarkEncodeDecodeData(useComplex, useCrypto)
{
  var format = WireFormat.getDefaultWireFormat() === BinaryXmlWireFormat.get() ? "ndnb" : "TLV ";
  var encoding = [];
  {
    var nIterations = useCrypto ? 8000 : 500000;
    var duration = TestEncodeDecodeBenchmark.benchmarkEncodeDataSeconds(nIterations, useComplex, useCrypto, encoding);
    console.log("Encode " + (useComplex ? "complex " : "simple  ") + format + " data: Crypto? " + (useCrypto ? "yes" : "no ") 
      + ", Duration sec, Hz: " + duration + ", " + (nIterations / duration));  
  }
  {
    var nIterations = useCrypto ? 50000 : 300000;
    var duration = TestEncodeDecodeBenchmark.benchmarkDecodeDataSeconds(nIterations, useCrypto, encoding[0]);
    console.log("Decode " + (useComplex ? "complex " : "simple  ") + format + " data: Crypto? " + (useCrypto ? "yes" : "no ") 
      + ", Duration sec, Hz: " + duration + ", " + (nIterations / duration));  
  }
}

// Make two passes, one for each wire format.
for (var i = 1; i <= 2; ++i) {
  if (i == 1)
    WireFormat.setDefaultWireFormat(BinaryXmlWireFormat.get());
  else
    WireFormat.setDefaultWireFormat(TlvWireFormat.get());

  benchmarkEncodeDecodeData(false, false);
  benchmarkEncodeDecodeData(true, false);
  benchmarkEncodeDecodeData(false, true);
  benchmarkEncodeDecodeData(true, true);
}

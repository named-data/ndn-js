var TestEncodeDecodeBenchmark = require("../browser/test-encode-decode-benchmark.js").TestEncodeDecodeBenchmark;

/**
 * Call benchmarkEncodeDataSeconds and benchmarkDecodeDataSeconds with appropriate nInterations.  Print the 
 * results to console.log.
 * @param {boolean} useComplex See benchmarkEncodeDataSeconds.
 * @param {boolean} useCrypto See benchmarkEncodeDataSeconds and benchmarkDecodeDataSeconds.
 */
function benchmarkEncodeDecodeData(useComplex, useCrypto)
{
  var encoding = [];
  {
    var nIterations = useCrypto ? 1 : 500000;
    var duration = TestEncodeDecodeBenchmark.benchmarkEncodeDataSeconds(nIterations, useComplex, useCrypto, encoding);
    console.log("Encode " + (useComplex ? "complex" : "simple ") + " data: Crypto? " + (useCrypto ? "yes" : "no ") 
      + ", Duration sec, Hz: " + duration + ", " + (nIterations / duration));  
  }
  {
    var nIterations = useCrypto ? 1 : 300000;
    var duration = TestEncodeDecodeBenchmark.benchmarkDecodeDataSeconds(nIterations, useCrypto, encoding[0]);
    console.log("Decode " + (useComplex ? "complex" : "simple ") + " data: Crypto? " + (useCrypto ? "yes" : "no ") 
      + ", Duration sec, Hz: " + duration + ", " + (nIterations / duration));  
  }
}

benchmarkEncodeDecodeData(false, false);

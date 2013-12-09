var TestEncodeDecodeBenchmark = require("../browser/test-encode-decode-benchmark.js").TestEncodeDecodeBenchmark;

var nIterations = 300000;
var duration = TestEncodeDecodeBenchmark.benchmarkDataDecodeSeconds(nIterations);
console.log("Data decode: Duration sec: " + duration + ", Hz: " + (nIterations / duration));  

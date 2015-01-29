/*
 * Copyright (C) 2014-2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

var TestEncodeDecodeBenchmark = require("../browser/test-encode-decode-benchmark.js").TestEncodeDecodeBenchmark;
var WireFormat = require('../..').WireFormat;
var BinaryXmlWireFormat = require('../..').BinaryXmlWireFormat;
var TlvWireFormat = require('../..').TlvWireFormat;

/**
 * Call benchmarkEncodeDataSeconds and benchmarkDecodeDataSeconds with appropriate nInterations.  Print the
 * results to console.log.
 * @param {boolean} useComplex See benchmarkEncodeDataSeconds.
 * @param {boolean} useCrypto See benchmarkEncodeDataSeconds and benchmarkDecodeDataSeconds.
 * @param {function} onFinished When finished, call onFinished(). It is necessary
 * to use a callback because the crypto functions use callbacks.
 */
function benchmarkEncodeDecodeData(useComplex, useCrypto, onFinished)
{
  var format = WireFormat.getDefaultWireFormat() === BinaryXmlWireFormat.get() ? "ndnb" : "TLV ";
  var encoding = [];
  {
    var nIterations = useCrypto ? 2000 : 500000;
    var duration = TestEncodeDecodeBenchmark.benchmarkEncodeDataSeconds(nIterations, useComplex, useCrypto, encoding);
    console.log("Encode " + (useComplex ? "complex " : "simple  ") + format + " data: Crypto? " + (useCrypto ? "RSA" : "no ")
      + ", Duration sec, Hz: " + duration + ", " + (nIterations / duration));
  }
  {
    var nIterations = useCrypto ? 20000 : 300000;
    var duration =
    TestEncodeDecodeBenchmark.benchmarkDecodeDataSeconds
      (nIterations, useCrypto, encoding[0], function(duration) {
        console.log("Decode " + (useComplex ? "complex " : "simple  ") + format + " data: Crypto? " + (useCrypto ? "RSA" : "no ")
          + ", Duration sec, Hz: " + duration + ", " + (nIterations / duration));
        onFinished();
      });
  }
}

// Make two passes, one for each wire format.
for (var i = 1; i <= 2; ++i) {
  if (i == 1)
    WireFormat.setDefaultWireFormat(BinaryXmlWireFormat.get());
  else
    WireFormat.setDefaultWireFormat(TlvWireFormat.get());

  benchmarkEncodeDecodeData(false, false, function() {
  benchmarkEncodeDecodeData(true, false, function() {
  benchmarkEncodeDecodeData(false, true, function() {
  benchmarkEncodeDecodeData(true, true, function() {});
  });
  });
  });
}

/**
 * Copyright (C) 2016 Regents of the University of California.
 * @author Andrew Brown <andrew.brown@intel.com>
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From jNDN TestControlResponse.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version, with the additional exemption that
 * compiling, linking, and/or using OpenSSL is allowed.
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

var assert = require('assert');
var Blob = require('../../..').Blob;
var ControlParameters = require('../../..').ControlParameters;
var ControlResponse = require('../../..').ControlResponse;

var TestControlResponse1 = new Buffer([
  0x65, 0x1c, // ControlResponse
    0x66, 0x02, 0x01, 0x94, // StatusCode
    0x67, 0x11, // StatusText
      0x4e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x6e, 0x6f, 0x74, 0x20,
      0x66, 0x6f, 0x75, 0x6e, 0x64,
    0x68, 0x03, // ControlParameters
      0x69, 0x01, 0x0a // FaceId
]);

describe('ControlResponse', function() {
  it('encode', function() {
    var response = new ControlResponse();
    response.setStatusCode(404);
    response.setStatusText("Nothing not found");
    response.setBodyAsControlParameters(new ControlParameters());
    response.getBodyAsControlParameters().setFaceId(10);
    var wire = response.wireEncode();

    assert.ok(wire.equals(new Blob(TestControlResponse1, false)));
  });

  it('decode', function() {
    var response = new ControlResponse();
    response.wireDecode(TestControlResponse1);

    assert.equal(response.getStatusCode(), 404);
    assert.equal(response.getStatusText(), "Nothing not found");
    assert.equal(response.getBodyAsControlParameters().getFaceId(), 10);
  });
});

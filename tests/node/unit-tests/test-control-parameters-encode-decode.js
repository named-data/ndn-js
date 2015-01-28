/**
 * Copyright (C) 2014-2015 Regents of the University of California.
 * @author: Andrew Brown <andrew.brown@intel.com>
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
var ControlParameters = require('../../../js/control-parameters').ControlParameters;
var Name = require('../../../js/name').Name;

describe('ControlParameters', function() {
  it('should encode and decode', function() {
    var parameters = new ControlParameters();
	parameters.setName(new Name('/test/control/parameters'));
	parameters.setFaceId(1);
	// encode
	var encoded = parameters.wireEncode();
	// decode
	var decodedParameters = new ControlParameters();
    decodedParameters.wireDecode(encoded);
    // compare
    assert.equal(parameters.getName().toUri(), decodedParameters
      .getName().toUri());
    assert.equal(parameters.getFaceId(), decodedParameters.getFaceId());
  });
  
  it('should encode and decode with no name', function() {
    var parameters = new ControlParameters();
	parameters.setStrategy(new Name('/localhost/nfd/strategy/broadcast'));
	parameters.setUri('null://');
	// encode
	var encoded = parameters.wireEncode();
	// decode
	var decodedParameters = new ControlParameters();
    decodedParameters.wireDecode(encoded);
    // compare
    assert.equal(parameters.getName().size(), 0);
	assert.equal(parameters.getStrategy().toUri(), decodedParameters
      .getStrategy().toUri());
    assert.equal(parameters.getUri(), decodedParameters.getUri());
  });
});

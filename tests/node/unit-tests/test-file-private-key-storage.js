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
var Name = require('../../../js/name').Name;
var KeyClass = require('../../../js/security/security-types').KeyClass;
var FilePrivateKeyStorage = require('../../../js/security/identity/file-private-key-storage').FilePrivateKeyStorage;

describe('FilePrivateKeyStorage', function () {
	var storage;

	beforeEach(function () {
		storage = new FilePrivateKeyStorage();
	});

	it('should read public key files from the right directory', function () {
		var key = storage.getPublicKey(new Name('/test/id/ksk-1421778442469'));
		assert.ok(key.getKeyType() !== null);
		assert.ok(key.getKeyDer().size() > 0);
	});
});

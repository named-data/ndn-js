/**
 * Copyright (C) 2014-2016 Regents of the University of California.
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
var fs = require('fs');
var path = require('path');
var Name = require('../../..').Name;
var KeyClass = require('../../..').KeyClass;
var RsaKeyParams = require('../../..').RsaKeyParams;
var DigestAlgorithm = require('../../..').DigestAlgorithm;
var FilePrivateKeyStorage = require('../../..').FilePrivateKeyStorage;

/**
 * Retrieve the user's current home directory. (Copy code from file-private-key-storage.js.)
 * @returns {string} path to the user's home directory
 */
function getUserHomePath() {
  return process.env.HOME || process.env.HOMEPATH || process.env.USERPROFILE;
}

var ndnFolder;

describe('FilePrivateKeyStorage', function () {
  /**
   * Create a few keys before testing.
   */
  before(function () {
    // (Copy code from file-private-key-storage.js.)
    ndnFolder = path.join(getUserHomePath(), '.ndn', 'ndnsec-tpm-file');

    // Create some test key files to use in tests.
    var instance = new FilePrivateKeyStorage();
    instance.generateKeyPair(new Name("/test/KEY/123"), new RsaKeyParams());
  });

  /**
   * Delete the keys we created
   */
  after(function () {
    // Delete all keys when done.
    var instance = new FilePrivateKeyStorage();
    try {
      instance.deleteKey(new Name("/test/KEY/123"));
      instance.deleteKey(new Name("/test/KEY/temp1"));
    }
    catch (e){
      console.log("Failed to clean up generated keys");
    }
  });

  /**
   * Test of generateKeyPair method, of class FilePrivateKeyStorage.
   */
  it('GenerateAndDeleteKeys', function () {
    // Create some more key files.
    var instance = new FilePrivateKeyStorage();
    instance.generateKeyPair(new Name("/test/KEY/temp1"), new RsaKeyParams());
    // Check if the files were created.
    var files = fs.readdirSync(ndnFolder);
    var createdFileCount = files.length;
    // 2 pre-created + 2 created now + some created by NFD
    assert.ok(createdFileCount >= 2, "Didn't create 2 files");
    // Delete these keys.
    instance.deleteKey(new Name("/test/KEY/temp1"));
    files = fs.readdirSync(ndnFolder);
    var deletedfileCount = files.length;
    assert.ok(createdFileCount - 2 == deletedfileCount, "Didn't delete 2 files");
  });

  /**
   * Test of doesKeyExist method, of class FilePrivateKeyStorage.
   */
  it('DoesKeyExist', function () {
    var instance = new FilePrivateKeyStorage();
    assert.ok(instance.doesKeyExist(new Name("/test/KEY/123"), KeyClass.PRIVATE));
    assert.ok(!instance.doesKeyExist(new Name("/unknown"), KeyClass.PRIVATE));
  });

  /**
   * Test of getPublicKey method, of class FilePrivateKeyStorage.
   */
  it('GetPublicKey', function () {
    var instance = new FilePrivateKeyStorage();
    var result = instance.getPublicKey(new Name("/test/KEY/123"));
    assert.notEqual(result, null);
  });

  /**
   * Test of sign method, of class FilePrivateKeyStorage.
   */
  it('Sign', function () {
    var data = new Buffer([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    var instance = new FilePrivateKeyStorage();
    var result = instance.sign(data, new Name("/test/KEY/123"), DigestAlgorithm.SHA256);
    assert.notEqual(result, null);
  });
});

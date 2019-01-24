/**
 * Copyright (C) 2014-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN unit-tests by Adeola Bannis.
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/name.t.cpp
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

var assert = require("assert");
var Name = require('../../..').Name;
var ComponentType = require('../../..').ComponentType;
var Blob = require('../../..').Blob;
var TlvWireFormat = require('../../..').TlvWireFormat;

var TEST_NAME = new Buffer([
  0x7,  0x14, // Name
    0x8,  0x5, // NameComponent
        0x6c,  0x6f,  0x63,  0x61,  0x6c,
    0x8,  0x3, // NameComponent
        0x6e,  0x64,  0x6e,
    0x8,  0x6, // NameComponent
        0x70,  0x72,  0x65,  0x66,  0x69,  0x78
]);

var TEST_NAME_IMPLICIT_DIGEST = new Buffer([
  0x7,  0x36, // Name
    0x8,  0x5, // NameComponent
        0x6c,  0x6f,  0x63,  0x61,  0x6c,
    0x8,  0x3, // NameComponent
        0x6e,  0x64,  0x6e,
    0x8,  0x6, // NameComponent
        0x70,  0x72,  0x65,  0x66,  0x69,  0x78,
    0x01, 0x20, // ImplicitSha256DigestComponent
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
]);

var TEST_NAME_PARAMETERS_DIGEST = new Buffer([
  0x7,  0x36, // Name
    0x8,  0x5, // NameComponent
        0x6c,  0x6f,  0x63,  0x61,  0x6c,
    0x8,  0x3, // NameComponent
        0x6e,  0x64,  0x6e,
    0x8,  0x6, // NameComponent
        0x70,  0x72,  0x65,  0x66,  0x69,  0x78,
    0x02, 0x20, // ParametersSha256DigestComponent
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
]);

var expectedURI;
var comp2;

describe('TestNameComponentMethods', function() {
  it('Unicode', function() {
    var comp1 = new Name.Component("entr\u00E9e");
    var expected = "entr%C3%A9e";
    assert.equal(comp1.toEscapedString(), expected, "Unicode URI not decoded correctly");
  });

  it('Compare', function() {
    var c7f = new Name("/%7F").get(0);
    var c80 = new Name("/%80").get(0);
    var c81 = new Name("/%81").get(0);

    assert.ok(c81.compare(c80) > 0, "%81 should be greater than %80");
    assert.ok(c80.compare(c7f) > 0, "%80 should be greater than %7f");
  });

  // Many more component methods to be tested!
});

describe('TestNameMethods', function() {
  beforeEach(function() {
    expectedURI = "/entr%C3%A9e/..../%00%01%02%03";
    comp2 = new Name.Component([0x00, 0x01, 0x02, 0x03]);
  });

  it('UriConstructor', function() {
    var name = new Name(expectedURI);
    assert.equal(name.size(), 3, 'Constructed name has ' + name.size() + ' components instead of 3');
    assert.equal(name.toUri(), expectedURI, 'URI is incorrect');
  });

  it('CopyConstructor', function() {
    var name = new Name(expectedURI);
    var name2 = new Name(name);
    assert.ok(name.equals(name2), 'Name from copy constructor does not match original');
  });

  it('GetComponent', function() {
    var name = new Name(expectedURI);
    var component2 = name.get(2);
    assert.ok(comp2.equals(component2), 'Component at index 2 is incorrect');
  });

  it('Append', function() {
    // could possibly split this into different tests
    var uri = "/localhost/user/folders/files/%00%0F";
    var name = new Name(uri);
    var name2 = new Name("/localhost").append(new Name("/user/folders/"));
    assert.equal(name2.size(), 3, 'Name constructed by appending names has ' + name2.size() + ' components instead of 3');
    assert.ok(name2.get(2).getValue().equals(new Blob("folders")), 'Name constructed with append has wrong suffix');
    name2.append("files");
    assert.equal(name2.size(), 4, 'Name constructed by appending string has ' + name2.size() + ' components instead of 4');
    name2.appendSegment(15);
    assert.ok(name2.get(4).getValue().equals(new Blob([0x00, 0x0F])), 'Name constructed by appending segment has wrong segment value');

    assert.ok(name2.equals(name), 'Name constructed with append is not equal to URI constructed name');
    assert.equal(name2.toUri(), name.toUri(), 'Name constructed with append has wrong URI');
  });

  it('Prefix', function() {
    var name = new Name("/edu/cmu/andrew/user/3498478");
    var name2 = name.getPrefix(2);
    assert.equal(name2.size(), 2, 'Name prefix has ' + name2.size() + ' components instead of 2');
    for (var i = 0; i < 2; ++i)
      assert.ok(name.get(i).getValue().equals(name2.get(i).getValue()));

    var prefix2 = name.getPrefix(100);
    assert.ok(prefix2.equals(name), "Prefix with more components than original should stop at end of original name");
  });

  it('Subname', function() {
    var name = new Name("/edu/cmu/andrew/user/3498478");
    var subName1 = name.getSubName(0);
    assert.ok(subName1.equals(name), 'Subname from first component does not match original name');
    var subName2 = name.getSubName(3);
    assert.equal(subName2.toUri(), "/user/3498478");

    var subName3 = name.getSubName(1, 3);
    assert.equal(subName3.toUri(), "/cmu/andrew/user");

    var subName4 = name.getSubName(0, 100);
    assert.ok(name.equals(subName4), 'Subname with more components than original should stop at end of original name');

    var subName5 = name.getSubName(7, 2);
    assert.ok(new Name().equals(subName5), 'Subname beginning after end of name should be empty');

    var subName6 = name.getSubName(-1,7);
    assert.ok(subName6.equals(new Name("/3498478")), "Negative subname with more components than original should stop at end of original name");

    var subName7 = name.getSubName(-5,5);
    assert.ok(subName7.equals(name), "Subname from (-length) should match original name");
  });

  it('Clear', function() {
    var name = new Name(expectedURI);
    name.clear();
    assert.ok(new Name().equals(name), 'Cleared name is not empty');
  });

  it('Compare', function() {
    var names = [ new Name("/a/b/d"), new Name("/c"), new Name("/c/a"), new Name("/bb"), new Name("/a/b/cc")];
    var expectedOrder = ["/a/b/d", "/a/b/cc", "/c", "/c/a", "/bb"];
    names.sort(function(a, b) { return a.compare(b); });

    var sortedURIs = [];
    for (var i = 0; i < names.length; ++i)
      sortedURIs.push(names[i].toUri());
    assert.deepEqual(sortedURIs, expectedOrder, 'Name comparison gave incorrect order');

    // Tests from ndn-cxx name.t.cpp Compare.
    assert.equal(new Name("/A")  .compare(new Name("/A")),    0);
    assert.equal(new Name("/A")  .compare(new Name("/A")),    0);
    assert.ok   (new Name("/A")  .compare(new Name("/B"))   < 0);
    assert.ok   (new Name("/B")  .compare(new Name("/A"))   > 0);
    assert.ok   (new Name("/A")  .compare(new Name("/AA"))  < 0);
    assert.ok   (new Name("/AA") .compare(new Name("/A"))   > 0);
    assert.ok   (new Name("/A")  .compare(new Name("/A/C")) < 0);
    assert.ok   (new Name("/A/C").compare(new Name("/A"))   > 0);

    assert.equal(new Name("/Z/A/Y")  .compare(1, 1, new Name("/A")),    0);
    assert.equal(new Name("/Z/A/Y")  .compare(1, 1, new Name("/A")),    0);
    assert.ok   (new Name("/Z/A/Y")  .compare(1, 1, new Name("/B"))   < 0);
    assert.ok   (new Name("/Z/B/Y")  .compare(1, 1, new Name("/A"))   > 0);
    assert.ok   (new Name("/Z/A/Y")  .compare(1, 1, new Name("/AA"))  < 0);
    assert.ok   (new Name("/Z/AA/Y") .compare(1, 1, new Name("/A"))   > 0);
    assert.ok   (new Name("/Z/A/Y")  .compare(1, 1, new Name("/A/C")) < 0);
    assert.ok   (new Name("/Z/A/C/Y").compare(1, 2, new Name("/A"))   > 0);

    assert.equal(new Name("/Z/A")  .compare(1, 9, new Name("/A")),    0);
    assert.equal(new Name("/Z/A")  .compare(1, 9, new Name("/A")),    0);
    assert.ok   (new Name("/Z/A")  .compare(1, 9, new Name("/B"))   < 0);
    assert.ok   (new Name("/Z/B")  .compare(1, 9, new Name("/A"))   > 0);
    assert.ok   (new Name("/Z/A")  .compare(1, 9, new Name("/AA"))  < 0);
    assert.ok   (new Name("/Z/AA") .compare(1, 9, new Name("/A"))   > 0);
    assert.ok   (new Name("/Z/A")  .compare(1, 9, new Name("/A/C")) < 0);
    assert.ok   (new Name("/Z/A/C").compare(1, 9, new Name("/A"))   > 0);

    assert.equal(new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/A/W"),   1, 1),  0);
    assert.equal(new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/A/W"),   1, 1),  0);
    assert.ok   (new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/B/W"),   1, 1) < 0);
    assert.ok   (new Name("/Z/B/Y")  .compare(1, 1, new Name("/X/A/W"),   1, 1) > 0);
    assert.ok   (new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/AA/W"),  1, 1) < 0);
    assert.ok   (new Name("/Z/AA/Y") .compare(1, 1, new Name("/X/A/W"),   1, 1) > 0);
    assert.ok   (new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/A/C/W"), 1, 2) < 0);
    assert.ok   (new Name("/Z/A/C/Y").compare(1, 2, new Name("/X/A/W"),   1, 1) > 0);

    assert.equal(new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/A"),   1),  0);
    assert.equal(new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/A"),   1),  0);
    assert.ok   (new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/B"),   1) < 0);
    assert.ok   (new Name("/Z/B/Y")  .compare(1, 1, new Name("/X/A"),   1) > 0);
    assert.ok   (new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/AA"),  1) < 0);
    assert.ok   (new Name("/Z/AA/Y") .compare(1, 1, new Name("/X/A"),   1) > 0);
    assert.ok   (new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/A/C"), 1) < 0);
    assert.ok   (new Name("/Z/A/C/Y").compare(1, 2, new Name("/X/A"),   1) > 0);
  });

  it('Match', function() {
    var name = new Name("/edu/cmu/andrew/user/3498478");
    var name1 = new Name(name);
    assert.ok(name.match(name1), 'Name does not match deep copy of itself');

    var name2 = name.getPrefix(2);
    assert.ok(name2.match(name), 'Name did not match prefix');
    assert.ok(!name.match(name2), 'Name should not match shorter name');
    assert.ok(new Name().match(name), 'Empty name should always match another');
  });

  it('GetSuccessor', function() {
    assert.ok(new Name("ndn:/%00%01/%01%03").equals(new Name("ndn:/%00%01/%01%02").getSuccessor()));
    assert.ok(new Name("ndn:/%00%01/%02%00").equals(new Name("ndn:/%00%01/%01%FF").getSuccessor()));
    assert.ok(new Name("ndn:/%00%01/%00%00%00").equals(new Name("ndn:/%00%01/%FF%FF").getSuccessor()));
    assert.ok(new Name("/sha256digest=0000000000000000000000000000000000000000000000000000000000000000").equals(new Name().getSuccessor()));
    assert.ok(new Name("/%00%01/%00").equals(new Name("/%00%01/...").getSuccessor()));
  });

  it('EncodeDecode', function() {
    var name = new Name("/local/ndn/prefix");

    var encoding = name.wireEncode(TlvWireFormat.get());
    assert.ok(encoding.equals(new Blob(TEST_NAME)));

    var decodedName = new Name();
    decodedName.wireDecode(new Blob(TEST_NAME), TlvWireFormat.get());
    assert.ok(decodedName.equals(name));

    // Test ImplicitSha256Digest.
    var name2 = new Name
      ("/local/ndn/prefix/sha256digest=" +
       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    var encoding2 = name2.wireEncode(TlvWireFormat.get());
    assert.ok(encoding2.equals(new Blob(TEST_NAME_IMPLICIT_DIGEST)));

    var decodedName2 = new Name();
    decodedName2.wireDecode(new Blob(TEST_NAME_IMPLICIT_DIGEST), TlvWireFormat.get());
    assert.ok(decodedName2.equals(name2));

    // Test ParametersSha256Digest.
    var name3 = new Name
      ("/local/ndn/prefix/params-sha256=" +
       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    var encoding3 = name3.wireEncode(TlvWireFormat.get());
    assert.ok(encoding3.equals(new Blob(TEST_NAME_PARAMETERS_DIGEST)));

    var decodedName3 = new Name();
    decodedName3.wireDecode(new Blob(TEST_NAME_PARAMETERS_DIGEST), TlvWireFormat.get());
    assert.ok(decodedName3.equals(name3));
  });

  it('ImplicitSha256Digest', function() {
    var name = new Name();

    var digest = new Buffer([
      0x28, 0xba, 0xd4, 0xb5, 0x27, 0x5b, 0xd3, 0x92,
      0xdb, 0xb6, 0x70, 0xc7, 0x5c, 0xf0, 0xb6, 0x6f,
      0x13, 0xf7, 0x94, 0x2b, 0x21, 0xe8, 0x0f, 0x55,
      0xc0, 0xe8, 0x6b, 0x37, 0x47, 0x53, 0xa5, 0x48,
      0x00, 0x00
    ]);

    name.appendImplicitSha256Digest(digest.slice(0, 32));
    name.appendImplicitSha256Digest(digest.slice(0, 32));
    assert.ok(name.get(0).equals(name.get(1)));

    var gotError = true;
    try {
      name.appendImplicitSha256Digest(digest.slice(0, 34));
      gotError = false;
    } catch (ex) {}
    if (!gotError)
      assert.fail("Expected error in appendImplicitSha256Digest");

    var gotError = true;
    try {
      name.appendImplicitSha256Digest(digest.slice(0, 30));
      gotError = false;
    } catch (ex) {}
    if (!gotError)
      assert.fail("Expected error in appendImplicitSha256Digest");

    // Add name.get(2) as a generic component.
    name.append(digest.slice(0, 32));
    assert.ok(name.get(0).compare(name.get(2)) < 0);
    assert.ok(name.get(0).getValue().equals(name.get(2).getValue()));

    // Add name.get(3) as a generic component whose first byte is greater.
    name.append(digest.slice(1, 32));
    assert.ok(name.get(0).compare(name.get(3)) < 0);

    assert.equal
      (name.get(0).toEscapedString(),
       "sha256digest=" +
       "28bad4b5275bd392dbb670c75cf0b66f13f7942b21e80f55c0e86b374753a548");

    assert.equal(name.get(0).isImplicitSha256Digest(), true);
    assert.equal(name.get(2).isImplicitSha256Digest(), false);

    gotError = true;
    try {
      new Name("/hello/sha256digest=hmm");
      gotError = false;
    } catch (ex) {}
    if (!gotError)
      assert.fail("Expected error in new Name from URI");

    // Check canonical URI encoding (lower case).
    var name2 = new Name
      ("/hello/sha256digest=" +
       "28bad4b5275bd392dbb670c75cf0b66f13f7942b21e80f55c0e86b374753a548");
    assert.ok(name.get(0).equals(name2.get(1)));

    // Check that it will accept a hex value in upper case too.
    name2 = new Name
      ("/hello/sha256digest=" +
       "28BAD4B5275BD392DBB670C75CF0B66F13F7942B21E80F55C0E86B374753A548");
    assert.ok(name.get(0).equals(name2.get(1)));
  });

  it('ParametersSha256Digest', function() {
    var name = new Name();

    var digest = new Buffer([
      0x28, 0xba, 0xd4, 0xb5, 0x27, 0x5b, 0xd3, 0x92,
      0xdb, 0xb6, 0x70, 0xc7, 0x5c, 0xf0, 0xb6, 0x6f,
      0x13, 0xf7, 0x94, 0x2b, 0x21, 0xe8, 0x0f, 0x55,
      0xc0, 0xe8, 0x6b, 0x37, 0x47, 0x53, 0xa5, 0x48,
      0x00, 0x00
    ]);

    name.appendParametersSha256Digest(digest.slice(0, 32));
    name.appendParametersSha256Digest(digest.slice(0, 32));
    assert.ok(name.get(0).equals(name.get(1)));

    var gotError = true;
    try {
      name.appendParametersSha256Digest(digest.slice(0, 34));
      gotError = false;
    } catch (ex) {}
    if (!gotError)
      assert.fail("Expected error in appendParametersSha256Digest");

    var gotError = true;
    try {
      name.appendParametersSha256Digest(digest.slice(0, 30));
      gotError = false;
    } catch (ex) {}
    if (!gotError)
      assert.fail("Expected error in appendParametersSha256Digest");

    // Add name.get(2) as a generic component.
    name.append(digest.slice(0, 32));
    assert.ok(name.get(0).compare(name.get(2)) < 0);
    assert.ok(name.get(0).getValue().equals(name.get(2).getValue()));

    // Add name.get(3) as a generic component whose first byte is greater.
    name.append(digest.slice(1, 32));
    assert.ok(name.get(0).compare(name.get(3)) < 0);

    assert.equal
      (name.get(0).toEscapedString(),
       "params-sha256=" +
       "28bad4b5275bd392dbb670c75cf0b66f13f7942b21e80f55c0e86b374753a548");

    assert.equal(name.get(0).isParametersSha256Digest(), true);
    assert.equal(name.get(2).isParametersSha256Digest(), false);

    gotError = true;
    try {
      new Name("/hello/params-sha256=hmm");
      gotError = false;
    } catch (ex) {}
    if (!gotError)
      assert.fail("Expected error in new Name from URI");

    // Check canonical URI encoding (lower case).
    var name2 = new Name
      ("/hello/params-sha256=" +
       "28bad4b5275bd392dbb670c75cf0b66f13f7942b21e80f55c0e86b374753a548");
    assert.ok(name.get(0).equals(name2.get(1)));

    // Check that it will accept a hex value in upper case too.
    name2 = new Name
      ("/hello/params-sha256=" +
       "28BAD4B5275BD392DBB670C75CF0B66F13F7942B21E80F55C0E86B374753A548");
    assert.ok(name.get(0).equals(name2.get(1)));
  });

  it('TypedNameComponent', function() {
    var otherTypeCode = 99;
    var uri = "/ndn/" + otherTypeCode + "=value";
    var name = new Name();
    name.append("ndn").append("value", ComponentType.OTHER_CODE, otherTypeCode);
    assert.equal(uri, name.toUri());

    var nameFromUri = new Name(uri);
    assert.equal("value", nameFromUri.get(1).getValue().toString());
    assert.equal(otherTypeCode, nameFromUri.get(1).getOtherTypeCode());

    var decodedName = new Name();
    decodedName.wireDecode(name.wireEncode());
    assert.equal("value", decodedName.get(1).getValue().toString());
    assert.equal(otherTypeCode, decodedName.get(1).getOtherTypeCode());
  });
});

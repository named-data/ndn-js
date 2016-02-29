/**
 * Copyright (C) 2014-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN unit-tests by Adeola Bannis.
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
var Blob = require('../../..').Blob;

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
    component2 = name.get(2);
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
    assert.ok(new Name("/%00").equals(new Name().getSuccessor()));
    assert.ok(new Name("/%00%01/%00").equals(new Name("/%00%01/...").getSuccessor()));
  });
});

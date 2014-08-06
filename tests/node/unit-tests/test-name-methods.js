/**                                                                                                            
 * Copyright (C) 2014 Regents of the University of California.                                                 
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>                                                              
 * From PyNDN unit-tests by Adelola Bannis.                                                                    
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
 * GNU General Public License for more details.                                                                
 *                                                                                                             
 * You should have received a copy of the GNU General Public License                                           
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.                                       
 * A copy of the GNU General Public License is in the file COPYING.                                            
 */

var assert = require("assert");
var Name = require('../../..').Name;
var Blob = require('../../..').Blob;

var expectedURI;
var comp2;

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

  it('Prefix', function() {
    var name = new Name(expectedURI);
    var name2 = name.getPrefix(2);
    assert.equal(name2.size(), 2, 'Name prefix has ' + name2.size() + ' components instead of 2');
    for (var i = 0; i < 2; ++i)
      assert.ok(name.get(i).getValue().equals(name2.get(i).getValue()));
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

    var subName5 = name.getSubName(7, 9);
    assert.ok(new Name().equals(subName5), 'Subname beginning after end of name should be empty');
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
});

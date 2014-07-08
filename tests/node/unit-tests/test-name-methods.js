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

describe('TestNameMethods', function() {
  it('UriConstructor', function() {
    var expectedUri = "/entr%C3%A9e/..../%00%01%02%03";
    var name = new Name(expectedUri);
    assert.equal(name.size(), 4);
    assert.equal(name.toUri(), expectedUri);
  });
});

describe('TestNameMethods', function() {
  it('CopyConstructor', function() {
    var expectedUri = "/entr%C3%A9e/..../%00%01%02%03";
    var name = new Name(expectedUri);
    var name2 = new Name(name);
    assert.equal(name.size(), 3);
    assert.ok(name.equals(name2));
  });
});

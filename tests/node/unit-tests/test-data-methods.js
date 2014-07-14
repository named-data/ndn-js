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
describe('TestDataMethods', function() {
  it('should return -1 when the value is not present', function() {
    assert.equal(-1, [1,2,3].indexOf(5));
    assert.equal(-1, [1,2,3].indexOf(0));
  });
});

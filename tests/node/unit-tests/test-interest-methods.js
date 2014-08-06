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
var Interest = require('../../..').Interest;
var KeyLocatorType = require('../../..').KeyLocatorType;
var Blob = require('../../..').Blob;

var codedInterest = new Buffer([
0x05, 0x53, // Interest
  0x07, 0x0A, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x03, 0x61, 0x62, 0x63, // Name
  0x09, 0x38, // Selectors
    0x0D, 0x01, 0x04, // MinSuffixComponents
    0x0E, 0x01, 0x06, // MaxSuffixComponents
    0x0F, 0x22, // KeyLocator
      0x1D, 0x20, // KeyLocatorDigest
                  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x10, 0x07, // Exclude
      0x08, 0x03, 0x61, 0x62, 0x63, // NameComponent
      0x13, 0x00, // Any
    0x11, 0x01, 0x01, // ChildSelector
    0x12, 0x00, // MustBeFesh
  0x0A, 0x04, 0x61, 0x62, 0x61, 0x62,   // Nonce
  0x0B, 0x01, 0x02, // Scope
  0x0C, 0x02, 0x75, 0x30, // InterestLifetime
1
]);

var initialDump = ['name: /ndn/abc',
  'minSuffixComponents: 4',
  'maxSuffixComponents: 6',
  'keyLocator: KeyLocatorDigest: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  'exclude: abc,*',
  'childSelector: 1',
  'mustBeFresh: true',
  'nonce: 61626162',
  'scope: 2',
  'lifetimeMilliseconds: 30000'];

function dump(s1, s2)
{
  var result = s1;
  if (s2)
    result += " " + s2;

  return result;
}


function dumpInterest(interest)
{
  var result = [];
  result.push(dump("name:", interest.getName().toUri()));
  result.push(dump("minSuffixComponents:",
    interest.getMinSuffixComponents() != null ?
      interest.getMinSuffixComponents() : "<none>"));
  result.push(dump("maxSuffixComponents:",
    interest.getMaxSuffixComponents() != null ?
      interest.getMaxSuffixComponents() : "<none>"));
  if (interest.getKeyLocator().getType() != null) {
    if (interest.getKeyLocator().getType() == KeyLocatorType.KEY_LOCATOR_DIGEST)
      result.push(dump("keyLocator: KeyLocatorDigest:",
        interest.getKeyLocator().getKeyData().toHex()));
    else if (interest.getKeyLocator().getType() == KeyLocatorType.KEYNAME)
      result.push(dump("keyLocator: KeyName:",
        interest.getKeyLocator().getKeyName().toUri()));
    else
      result.push(dump("keyLocator: <unrecognized KeyLocatorType"));
  }
  else
    result.push(dump("keyLocator: <none>"));
  result.push(dump("exclude:",
    interest.getExclude().size() > 0 ? interest.getExclude().toUri() :"<none>"));
  result.push(dump("childSelector:",
    interest.getChildSelector() != null ? interest.getChildSelector() : "<none>"));
  result.push(dump("mustBeFresh:", interest.getMustBeFresh()));
  result.push(dump("nonce:", interest.getNonce().size() == 0 ?
    "<none>" : interest.getNonce().toHex()));
  result.push(dump("scope:", interest.getScope() == null ? 
    "<none>" : interest.getScope()));
  result.push(dump("lifetimeMilliseconds:",
    interest.getInterestLifetimeMilliseconds() == null ?
      "<none>" : interest.getInterestLifetimeMilliseconds()));
  return result;
}

/**
 * Return a copy of the strings array, removing any string that start with prefix.
 */
function removeStartingWith(strings, prefix)
{
  var result = [];
  for (var i = 0; i < strings.length; ++i) {
    if (strings[i].substr(0, prefix.length) != prefix)
      result.push(strings[i]);
  }

  return result;
}

// ignoring nonce, check that the dumped interests are equal
function interestDumpsEqual(dump1, dump2)
{
  var prefix = "nonce:";
  dump1 = removeStartingWith(dump1, prefix);
  dump2 = removeStartingWith(dump2, prefix);

  if (dump1.length != dump2.length)
    return false;
  for (var i = 0; i < dump1.length; ++i) {
    if (dump1[i] != dump2[i])
      return false;
  }
  return true;
}

function createFreshInterest()
{
  var freshInterest = new Interest(new Name("/ndn/abc"));
  freshInterest.setMustBeFresh(false);
  freshInterest.setMinSuffixComponents(4);
  freshInterest.setMaxSuffixComponents(6);
  freshInterest.getKeyLocator().setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
  freshInterest.getKeyLocator().setKeyData(new Blob(
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F], false));
  freshInterest.getExclude().appendComponent(new Name("abc").get(0)).appendAny();
  freshInterest.setInterestLifetimeMilliseconds(30000);
  freshInterest.setChildSelector(1);
  freshInterest.setMustBeFresh(true);
  freshInterest.setScope(2);

  return freshInterest;
}

var referenceInterest;

describe('TestInterestDump', function() {
  beforeEach(function() {
    referenceInterest = new Interest();
    referenceInterest.wireDecode(codedInterest);
  });

  it('Dump', function() {
    // see if the dump format is the same as we expect
    var decodedDump = dumpInterest(referenceInterest);
    assert.deepEqual(initialDump, decodedDump, 'Initial dump does not have expected format');
  });

  it('Redecode', function() {
    // check that we encode and decode correctly
    var encoding = referenceInterest.wireEncode();
    var reDecodedInterest = new Interest();
    reDecodedInterest.wireDecode(encoding);
    var redecodedDump = dumpInterest(reDecodedInterest);
    assert.deepEqual(initialDump, redecodedDump, 'Re-decoded interest does not match original');
  });

  it('CreateFresh', function() {
    var freshInterest = createFreshInterest();
    var freshDump = dumpInterest(freshInterest);
    assert.ok(interestDumpsEqual(initialDump, freshDump), 'Fresh interest does not match original');

    var reDecodedFreshInterest = new Interest();
    reDecodedFreshInterest.wireDecode(freshInterest.wireEncode());
    var reDecodedFreshDump = dumpInterest(reDecodedFreshInterest);

    assert.ok(interestDumpsEqual(freshDump, reDecodedFreshDump), 'Redecoded fresh interest does not match original');
  });
});


describe('TestInterestMethods', function() {
  beforeEach(function() {
    referenceInterest = new Interest();
    referenceInterest.wireDecode(codedInterest);
  });

  it('CopyConstructor', function() {
    var interest = new Interest(referenceInterest);
    assert.ok(interestDumpsEqual(dumpInterest(interest), dumpInterest(referenceInterest)), 'Interest constructed as deep copy does not match original');
  });

  it('EmptyNonce', function() {
    // make sure a freshly created interest has no nonce
    var freshInterest = createFreshInterest();
    assert.ok(freshInterest.getNonce().isNull(), 'Freshly created interest should not have a nonce');
  });

  it('SetRemovesNonce', function() {
    // Ensure that changing a value on an interest clears the nonce.
    assert.ok(!referenceInterest.getNonce().isNull());
    var interest = new Interest(referenceInterest);
    // Change a child object.
    /* TODO: Implement ChangeCounter in Interest to detect changes in child objects.
    interest.getExclude().clear();
    */
    interest.setChildSelector(0);
    assert.ok(interest.getNonce().isNull(), 'Interest should not have a nonce after changing fields');
  });
});

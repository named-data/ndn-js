/**
 * Copyright (C) 2014-2019 Regents of the University of California.
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
var Interest = require('../../..').Interest;
var Exclude = require('../../..').Exclude;
var Data = require('../../..').Data;
var KeyLocator = require('../../..').KeyLocator;
var Sha256WithRsaSignature = require('../../..').Sha256WithRsaSignature;
var DigestSha256Signature = require('../../..').DigestSha256Signature;
var KeyLocatorType = require('../../..').KeyLocatorType;
var Blob = require('../../..').Blob;
var MemoryIdentityStorage = require('../../..').MemoryIdentityStorage;
var MemoryPrivateKeyStorage = require('../../..').MemoryPrivateKeyStorage;
var IdentityManager = require('../../..').IdentityManager;
var SelfVerifyPolicyManager = require('../../..').SelfVerifyPolicyManager;
var KeyChain = require('../../..').KeyChain;
var InterestFilter = require('../../..').InterestFilter;

var codedInterest = new Buffer([
0x05, 0x5C, // Interest
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
  0x0C, 0x02, 0x75, 0x30, // InterestLifetime
  0x1e, 0x0a, // ForwardingHint
        0x1f, 0x08, // Delegation
              0x1e, 0x01, 0x01, // Preference=1
              0x07, 0x03, 0x08, 0x01, 0x41, // Name=/A
1
]);

var codedInterestNoSelectors = new Buffer([
0x05, 0x12, // Interest
  0x07, 0x0A, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x03, 0x61, 0x62, 0x63, // Name
  0x0A, 0x04, 0x61, 0x62, 0x61, 0x62   // Nonce
]);

var initialDump = ['name: /ndn/abc',
  'minSuffixComponents: 4',
  'maxSuffixComponents: 6',
  'keyLocator: KeyLocatorDigest: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  'exclude: abc,*',
  'childSelector: 1',
  'mustBeFresh: true',
  'nonce: 61626162',
  'lifetimeMilliseconds: 30000',
  'forwardingHint:',
  '  Preference: 1, Name: /A'];

var simpleCodedInterestV03 = new Buffer([
0x05, 0x07, // Interest
  0x07, 0x03, 0x08, 0x01, 0x49, // Name = /I
  0x12, 0x00, // MustBeFresh
]);

var simpleCodedInterestV03Dump = [
  "name: /I",
  "minSuffixComponents: <none>",
  "maxSuffixComponents: 1",
  "keyLocator: <none>",
  "exclude: <none>",
  "childSelector: <none>",
  "mustBeFresh: true",
  "nonce: <none>",
  "lifetimeMilliseconds: <none>",
  "forwardingHint: <none>"];

var fullCodedInterestV03 = new Buffer([
0x05, 0x29, // Interest
  0x07, 0x03, 0x08, 0x01, 0x49, // Name = /I
  0x21, 0x00, // CanBePrefix
  0x12, 0x00, // MustBeFresh
  0x1E, 0x0B, // ForwardingHint
    0x1F, 0x09, // Delegation
      0x1E, 0x02, 0x01, 0x00, // Preference = 256
      0x07, 0x03, 0x08, 0x01, 0x48, // Name = /H
  0x0A, 0x04, 0x12, 0x34, 0x56, 0x78, // Nonce
  0x0C, 0x02, 0x10, 0x00, // InterestLifetime = 4096
  0x22, 0x01, 0xD6, // HopLimit
  0x24, 0x04, 0xC0, 0xC1, 0xC2, 0xC3 // ApplicationParameters
]);

var fullCodedInterestV03Dump = [
    "name: /I",
    "minSuffixComponents: <none>",
    "maxSuffixComponents: <none>",
    "keyLocator: <none>",
    "exclude: <none>",
    "childSelector: <none>",
    "mustBeFresh: true",
    "nonce: 12345678",
    "lifetimeMilliseconds: 4096",
    "forwardingHint:",
    "  Preference: 256, Name: /H"];

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
  result.push(dump("lifetimeMilliseconds:",
    interest.getInterestLifetimeMilliseconds() == null ?
      "<none>" : interest.getInterestLifetimeMilliseconds()));
  if (interest.getForwardingHint().size() > 0) {
    result.push(dump("forwardingHint:"));
    for (var i = 0; i < interest.getForwardingHint().size(); ++i)
      result.push(dump("  Preference: " +
        interest.getForwardingHint().get(i).getPreference() + ", Name: " +
        interest.getForwardingHint().get(i).getName().toUri()));
  }
  else
    result.push(dump("forwardingHint: <none>"));
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
  var freshInterest = new Interest(new Name("/ndn/abc"))
    .setMustBeFresh(false)
    .setMinSuffixComponents(4)
    .setMaxSuffixComponents(6)
    .setInterestLifetimeMilliseconds(30000)
    .setChildSelector(1)
    .setMustBeFresh(true);
  freshInterest.getKeyLocator().setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
  freshInterest.getKeyLocator().setKeyData(new Blob(
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F], false));
  freshInterest.getExclude().appendComponent(new Name("abc").get(0)).appendAny();
  freshInterest.getForwardingHint().add(1, new Name("/A"));

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

  it('RedecodeImplicitDigestExclude', function() {
    // Check that we encode and decode correctly with an implicit digest exclude.
    var interest = new Interest(new Name("/A"));
    interest.getExclude().appendComponent(new Name("/sha256digest=" +
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").get(0));
    var dump = dumpInterest(interest);

    var encoding = interest.wireEncode();
    var reDecodedInterest = new Interest();
    reDecodedInterest.wireDecode(encoding);
    var redecodedDump = dumpInterest(reDecodedInterest);
    assert.ok(interestDumpsEqual(dump, redecodedDump),
                                 'Re-decoded interest does not match original');
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

  it('NoSelectorsMustBeFresh', function() {
    var interest = new Interest();
    interest.wireDecode(codedInterestNoSelectors);
    assert.equal(false, interest.getMustBeFresh(),
      "MustBeFresh should be false if no selectors");
  });

  it('DecodeV03AsV02', function() {
    var interest1 = new Interest();
    interest1.wireDecode(simpleCodedInterestV03);

    var dump1 = dumpInterest(interest1);
    assert.deepEqual(dump1, simpleCodedInterestV03Dump,
      "Decoded simpleCodedInterestV03 does not match the dump");

    var interest2 = new Interest();
    interest2.wireDecode(fullCodedInterestV03);

    var dump2 = dumpInterest(interest2);
    assert.deepEqual(dump2, fullCodedInterestV03Dump,
      "Decoded fullCodedInterestV03Dump does not match the dump");
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
    interest.getExclude().clear();
    assert.ok(interest.getNonce().isNull(), 'Interest should not have a nonce after changing fields');
  });

  it('RefreshNonce', function() {
    var interest = new Interest(referenceInterest);
    var oldNonce = interest.getNonce();
    assert.equal(oldNonce.size(), 4);

    interest.refreshNonce();
    assert.equal(interest.getNonce().size(), oldNonce.size(),
                 "The refreshed nonce should be the same size");
    assert.equal(interest.getNonce().equals(oldNonce), false,
                 "The refreshed nonce should be different");
  });

  it('ExcludeMatches', function() {
    var exclude = new Exclude();
    exclude.appendComponent(new Name("%00%02").get(0));
    exclude.appendAny();
    exclude.appendComponent(new Name("%00%20").get(0));

    var component;
    component = new Name("%00%01").get(0);
    assert.ok(!exclude.matches(component),
      component.toEscapedString() + " should not match " + exclude.toUri());
    component = new Name("%00%0F").get(0);
    assert.ok(exclude.matches(component),
      component.toEscapedString() + " should match " + exclude.toUri());
    component = new Name("%00%21").get(0);
    assert.ok(!exclude.matches(component),
      component.toEscapedString() + " should not match " + exclude.toUri());
  });

  it('VerifyDigestSha256', function() {
    // Create a KeyChain but we don't need to add keys.
    var identityStorage = new MemoryIdentityStorage();
    var privateKeyStorage = new MemoryPrivateKeyStorage();
    var keyChain = new KeyChain
      (new IdentityManager(identityStorage, privateKeyStorage),
       new SelfVerifyPolicyManager(identityStorage));

    var interest = new Interest(new Name("/test/signed-interest"));
    keyChain.signWithSha256(interest);

    // We create simple callbacks to count calls since we're not interested in
    //   the effect of the callbacks themselves.
    var failedCallCount = 0;
    var verifiedCallCount = 0;

    keyChain.verifyInterest
      (interest, function() { ++verifiedCallCount; },
       function() { ++failedCallCount; });
    assert.equal(failedCallCount, 0, 'Signature verification failed');
    assert.equal(verifiedCallCount, 1, 'Verification callback was not used.');
  });

  it('MatchesData', function() {
    var interest = new Interest(new Name("/A"));
    interest.setMinSuffixComponents(2);
    interest.setMaxSuffixComponents(2);
    interest.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    interest.getKeyLocator().setKeyName(new Name("/B"));
    interest.getExclude().appendComponent(new Name.Component("J"));
    interest.getExclude().appendAny();

    var data = new Data(new Name("/A/D"));
    var signature = new Sha256WithRsaSignature();
    signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    signature.getKeyLocator().setKeyName(new Name("/B"));
    data.setSignature(signature);
    assert.equal(interest.matchesData(data), true);

    // Check violating MinSuffixComponents.
    var data1 = new Data(data);
    data1.setName(new Name("/A"));
    assert.equal(interest.matchesData(data1), false);

    var interest1 = new Interest(interest);
    interest1.setMinSuffixComponents(1);
    assert.equal(interest1.matchesData(data1), true);

    // Check violating MaxSuffixComponents.
    var data2 = new Data(data);
    data2.setName(new Name("/A/E/F"));
    assert.equal(interest.matchesData(data2), false);

    var interest2 = new Interest(interest);
    interest2.setMaxSuffixComponents(3);
    assert.equal(interest2.matchesData(data2), true);

    // Check violating PublisherPublicKeyLocator.
    var data3 = new Data(data);
    var signature3 = new Sha256WithRsaSignature();
    signature3.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    signature3.getKeyLocator().setKeyName(new Name("/G"));
    data3.setSignature(signature3);
    assert.equal(interest.matchesData(data3), false);

    var interest3 = new Interest(interest);
    interest3.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    interest3.getKeyLocator().setKeyName(new Name("/G"));
    assert.equal(interest3.matchesData(data3), true);

    var data4 = new Data(data);
    data4.setSignature(new DigestSha256Signature());
    assert.equal(interest.matchesData(data4), false);

    var interest4 = new Interest(interest);
    interest4.setKeyLocator(new KeyLocator());
    assert.equal(interest4.matchesData(data4), true);

    // Check violating Exclude.
    var data5 = new Data(data);
    data5.setName(new Name("/A/J"));
    assert.equal(interest.matchesData(data5), false);

    var interest5 = new Interest(interest);
    interest5.getExclude().clear();
    interest5.getExclude().appendComponent(new Name.Component("K"));
    interest5.getExclude().appendAny();
    assert.equal(interest5.matchesData(data5), true);

    // Check violating Name.
    var data6 = new Data(data);
    data6.setName(new Name("/H/I"));
    assert.equal(interest.matchesData(data6), false);

    var data7 = new Data(data);
    data7.setName(new Name("/A/B"));

    var interest7 = new Interest
      (new Name("/A/B/sha256digest=" +
                "54008e240a7eea2714a161dfddf0dd6ced223b3856e9da96792151e180f3b128"));
    assert.equal(interest7.matchesData(data7), true);

    // Check violating the implicit digest.
    var interest7b = new Interest
      (new Name("/A/B/%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00" +
                     "%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00"));
    assert.equal(interest7b.matchesData(data7), false);

    // Check excluding the implicit digest.
    var interest8 = new Interest(new Name("/A/B"));
    interest8.getExclude().appendComponent(interest7.getName().get(2));
    assert.equal(interest8.matchesData(data7), false);
  });

  it('InterestFilterMatching', function() {
    // From ndn-cxx interest.t.cpp.
    assert.equal(true,  new InterestFilter("/a").doesMatch(new Name("/a/b")));
    assert.equal(true,  new InterestFilter("/a/b").doesMatch(new Name("/a/b")));
    assert.equal(false, new InterestFilter("/a/b/c").doesMatch(new Name("/a/b")));

    assert.equal(true,  new InterestFilter("/a", "<b>").doesMatch(new Name("/a/b")));
    assert.equal(false, new InterestFilter("/a/b", "<b>").doesMatch(new Name("/a/b")));

    assert.equal(false, new InterestFilter("/a/b", "<c>").doesMatch(new Name("/a/b/c/d")));
    assert.equal(false, new InterestFilter("/a/b", "<b>").doesMatch(new Name("/a/b/c/b")));
    assert.equal(true,  new InterestFilter("/a/b", "<>*<b>").doesMatch(new Name("/a/b/c/b")));

    assert.equal(false, new InterestFilter("/a", "<b>").doesMatch(new Name("/a/b/c/d")));
    assert.equal(true,  new InterestFilter("/a", "<b><>*").doesMatch(new Name("/a/b/c/d")));
    assert.equal(true,  new InterestFilter("/a", "<b><>*").doesMatch(new Name("/a/b")));
    assert.equal(false, new InterestFilter("/a", "<b><>+").doesMatch(new Name("/a/b")));
    assert.equal(true,  new InterestFilter("/a", "<b><>+").doesMatch(new Name("/a/b/c")));
  });

  it('SetApplicationParameters', function() {
    var interest = new Interest("/ndn");
    assert.ok(!interest.hasApplicationParameters());
    var applicationParameters = new Blob(new Buffer([ 0x23, 0x00 ]));
    interest.setApplicationParameters(applicationParameters);
    assert.ok(interest.hasApplicationParameters());
    assert.ok(interest.getApplicationParameters().equals(applicationParameters));

    var decodedInterest = new Interest();
    decodedInterest.wireDecode(interest.wireEncode());
    assert.ok(decodedInterest.getApplicationParameters().equals(applicationParameters));

    interest.setApplicationParameters(new Blob());
    assert.ok(!interest.hasApplicationParameters());
  });

  it('AppendParametersDigest', function() {
    var name = new Name("/local/ndn/prefix");
    var interest = new Interest(name);

    assert.ok(!interest.hasApplicationParameters());
    // No parameters yet, so it should do nothing.
    interest.appendParametersDigestToName();
    assert.equal("/local/ndn/prefix", interest.getName().toUri());

    var applicationParameters = new Blob(new Buffer([ 0x23, 0x01, 0xC0 ]));
    interest.setApplicationParameters(applicationParameters);
    assert.ok(interest.hasApplicationParameters());
    interest.appendParametersDigestToName();
    assert.equal(name.size() + 1, interest.getName().size());
    assert.ok(interest.getName().getPrefix(-1).equals(name));
    var SHA256_LENGTH = 32;
    assert.equal(SHA256_LENGTH, interest.getName().get(-1).getValue().size());

    assert.equal(interest.getName().toUri(), "/local/ndn/prefix/" +
      "params-sha256=a16cc669b4c9ef6801e1569488513f9523ffb28a39e53aa6e11add8d00a413fc");
  });
});

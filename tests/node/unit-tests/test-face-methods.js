/**
 * Copyright (C) 2014-2015 Regents of the University of California.
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
var Face = require('../../..').Face;

// Returns an object with , so we can test onData and timeout behavior.

/**
 * Use interestName to express an interest to test onData and timeout behavior.
 * The overall test case timeout is set by the --timeout parameter on the
 * Mocha command line, e.g. --timeout 10000 .
 * @param {type} done The Mocha done object which is called by the
 * expressInterest callbacks to tell Mocha to continue.
 * @param {Face} face The Face object for calling expressInterest.
 * @param {Name} interestName The name for the interest.
 * @returns {object} An object with onDataCallCount and onTimeoutCallCount,
 * as well as the interest and data objects given to the callback. Note that
 * Mocha should wait until the callback calls done before continuing to check
 * the returned object.
 */
function runExpressNameTest(done, face, interestName)
{
  var name = new Name(interestName);
  var counter = { onDataCallCount: 0, onTimeoutCallCount: 0,
                 interest: null, data: null };
  face.expressInterest
    (name,
     function(interest, data) {
       counter.interest = interest;
       counter.data = data;
       ++counter.onDataCallCount;
       // Mocha doesn't like "done" being called multiple times, so only call the first time.
       if (counter.onDataCallCount == 1)
         done();
     },
     function(interest) {
       counter.interest = interest;
       ++counter.onTimeoutCallCount;
       // Mocha doesn't like "done" being called multiple times, so only call the first time.
       if (counter.onTimeoutCallCount == 1)
         done();
     });

  return counter;
}

var face;
var uri;
var counter;
var interestID;

describe('TestFaceInterestMethods', function() {
  // Mocha will wait until a callback calls "done" before running the "it" test.
  before(function(done) {
    face = new Face({host: "localhost"});
    uri = "/";
    counter = runExpressNameTest(done, face, uri);
  });

  it('AnyInterest', function() {
    assert.ok(counter.onTimeoutCallCount == 0, 'Timeout on expressed interest');

    // check that the callback was correct
    assert.equal(counter.onDataCallCount, 1, 'Expected 1 onData callback, got ' + counter.onDataCallCount);

    // just check that the interest was returned correctly?
    var callbackInterest = counter.interest;
    assert.ok(callbackInterest.getName().equals(new Name(uri)), 'Interest returned on callback had different name');
  });
});

/*
TODO: Replace this with a test that connects to a Face on localhost
def test_specific_interest(self):
  uri = "/ndn/edu/ucla/remap/ndn-js-test/howdy.txt/%FD%052%A1%DF%5E%A4"
  (dataCallback, timeoutCallback) = self.run_express_name_test(uri)
  self.assertTrue(timeoutCallback.call_count == 0, 'Unexpected timeout on expressed interest')

  // check that the callback was correct
  self.assertEqual(dataCallback.call_count, 1, 'Expected 1 onData callback, got '+str(dataCallback.call_count))

  onDataArgs = dataCallback.call_args[0] # the args are returned as ([ordered arguments], [keyword arguments])

  // just check that the interest was returned correctly?
  callbackInterest = onDataArgs[0]
  self.assertTrue(callbackInterest.getName().equals(Name(uri)), 'Interest returned on callback had different name')
*/

describe('TestFaceInterestMethods', function() {
  // Mocha will wait until a callback calls "done" before running the "it" test.
  before(function(done) {
    uri = "/test/timeout";
    counter = runExpressNameTest(done, face, uri);
  });

  it('Timeout', function() {
    // we're expecting a timeout callback, and only 1
    assert.ok(counter.onDataCallCount == 0, 'Data callback called for invalid interest');

    assert.ok(counter.onTimeoutCallCount == 1, 'Expected 1 timeout call, got ' + counter.onTimeoutCallCount);

    // just check that the interest was returned correctly?
    var callbackInterest = counter.interest;
    assert.ok(callbackInterest.getName().equals(new Name(uri)), 'Interest returned on callback had different name');
  });
});

describe('TestFaceInterestMethods', function() {
  // Mocha will wait until a callback calls "done" before running the "it" test.
  before(function(done) {
    var name = new Name("/ndn/edu/ucla/remap/");
    counter = { onDataCallCount: 0, onTimeoutCallCount: 0 };

    interestID = face.expressInterest
      (name,
       function(interest, data) {
         ++counter.onDataCallCount;
         // Mocha doesn't like "done" being called multiple times, so only call the first time.
         if (counter.onDataCallCount == 1)
           done();
       },
       function(interest) {
         ++counter.onTimeoutCallCount;
         // Mocha doesn't like "done" being called multiple times, so only call the first time.
         if (counter.onTimeoutCallCount == 1)
           done();
       });

    // Set a timeout to call done if not called by onData or onTimeout. We wait
    //   longer than the interest timeout (about 4000 ms) but shorter than the
    //   Mocha test timeout (about 10000 ms).
    setTimeout(function() {
      if (counter.onDataCallCount == 0 && counter.onTimeoutCallCount == 0)
        done();
    }, 8000);

    face.removePendingInterest(interestID);
  });

  it('RemovePending', function() {
    assert.equal(counter.onDataCallCount, 0, 'Should not have called data callback after interest was removed');
    assert.equal(counter.onTimeoutCallCount, 0, 'Should not have called timeout callback after interest was removed');
  });
});

describe('TestFaceInterestMethods', function() {
  it('MaxNdnPacketSize', function() {
    // Construct an interest whose encoding is one byte larger than getMaxNdnPacketSize.
    var targetSize = Face.getMaxNdnPacketSize() + 1;
    // Start with an interest which is almost the right size.
    var interest = new Interest();
    interest.getName().append(new Buffer(targetSize));
    var initialSize = interest.wireEncode().size();
    // Now replace the component with the desired size which trims off the extra encoding.
    interest.setName
      (new Name().append(new Buffer(targetSize - (initialSize - targetSize))));
    var interestSize = interest.wireEncode().size();
    assert.equal(targetSize, interestSize,  "Wrong interest size for MaxNdnPacketSize");

    assert.throws
      (function() {
         face.expressInterest
           (interest, function(interest, data) {}, function(interest) {}); },
       Error,
       "expressInterest didn't throw an exception when the interest size exceeds getMaxNdnPacketSize()");
  });
});

/**
 * Copyright (C) 2014-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx NamingConventions unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/test-name.cpp.
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

describe('TestNameConventions', function() {
  it('NumberWithMarker', function() {
    var expected = new Name("/%AA%03%E8");
    var number = 1000;
    var marker = 0xAA;
    assert.ok(new Name().append(Name.Component.fromNumberWithMarker(number, marker)).equals(expected), "fromNumberWithMarker did not create the expected component");
    assert.equal(expected.get(0).toNumberWithMarker(marker), number, "toNumberWithMarker did not return the expected value");
  });

  it('Segment', function() {
    var expected = new Name("/%00%27%10");
    assert.ok(expected.get(0).isSegment());
    var number = 10000;
    assert.ok(new Name().appendSegment(number).equals(expected), "appendSegment did not create the expected component");
    assert.equal(expected.get(0).toSegment(), number, "toSegment did not return the expected value");
  });

  it('SegmentOffset', function() {
    var expected = new Name("/%FB%00%01%86%A0");
    assert.ok(expected.get(0).isSegmentOffset());
    var number = 100000;
    assert.ok(new Name().appendSegmentOffset(number).equals(expected), "appendSegmentOffset did not create the expected component");
    assert.equal(expected.get(0).toSegmentOffset(), number, "toSegmentOffset did not return the expected value");
  });

  it('Version', function() {
    var expected = new Name("/%FD%00%0FB%40");
    assert.ok(expected.get(0).isVersion());
    var number = 1000000;
    assert.ok(new Name().appendVersion(number).equals(expected), "appendVersion did not create the expected component");
    assert.equal(expected.get(0).toVersion(), number, "toVersion did not return the expected value");
  });

  it('SequenceNumber', function() {
    var expected = new Name("/%FE%00%98%96%80");
    assert.ok(expected.get(0).isSequenceNumber());
    var number = 10000000;
    assert.ok(new Name().appendSequenceNumber(number).equals(expected), "appendSequenceNumber did not create the expected component");
    assert.equal(expected.get(0).toSequenceNumber(), number, "toSequenceNumber did not return the expected value");
  });

  it('Timestamp', function() {
    var expected = new Name("/%FC%00%04%7BE%E3%1B%00%00");
    assert.ok(expected.get(0).isTimestamp());
    // 40 years (not counting leap years) in microseconds.
    var number = 40 * 365 * 24 * 3600 * 1000000;
    assert.ok(new Name().appendTimestamp(number).equals(expected), "appendTimestamp did not create the expected component");
    assert.equal(expected.get(0).toTimestamp(), number, "toTimestamp did not return the expected value");
  });
});

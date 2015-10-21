/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/interval.t.cpp
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
var Interval = require('../../..').Interval;
var Certificate = require('../../..').Certificate;

describe('TestInterval', function() {
  it('Construction', function() {
    // Construct with the right parameters.
    var interval1 = new Interval(Certificate.fromIsoString("20150825T120000"),
                                 Certificate.fromIsoString("20150825T160000"));
    assert.ok("20150825T120000" == Certificate.toIsoString(interval1.getStartTime()));
    assert.ok("20150825T160000" == Certificate.toIsoString(interval1.getEndTime()));
    assert.ok(interval1.isValid());

    // Construct with the invalid interval.
    var interval2 = new Interval();
    assert.ok(!interval2.isValid());

    // Construct with the empty interval.
    var interval3 = new Interval(true);
    assert.ok(interval3.isValid());
    assert.ok(interval3.isEmpty());
  });

  it('CoverTimePoint', function() {
    var interval = new Interval(Certificate.fromIsoString("20150825T120000"),
                                Certificate.fromIsoString("20150825T160000"));

    var timePoint1 = Certificate.fromIsoString("20150825T120000");
    var timePoint2 = Certificate.fromIsoString("20150825T130000");
    var timePoint3 = Certificate.fromIsoString("20150825T170000");
    var timePoint4 = Certificate.fromIsoString("20150825T110000");

    assert.ok(interval.covers(timePoint1));
    assert.ok(interval.covers(timePoint2));
    assert.ok(!interval.covers(timePoint3));
    assert.ok(!interval.covers(timePoint4));
  });

  it('IntersectionAndUnion', function() {
    var interval1 = new Interval(Certificate.fromIsoString("20150825T030000"),
                                 Certificate.fromIsoString("20150825T050000"));
    // No intersection.
    var interval2 = new Interval(Certificate.fromIsoString("20150825T050000"),
                                 Certificate.fromIsoString("20150825T070000"));
    // No intersection.
    var interval3 = new Interval(Certificate.fromIsoString("20150825T060000"),
                                 Certificate.fromIsoString("20150825T070000"));
    // There's an intersection.
    var interval4 = new Interval(Certificate.fromIsoString("20150825T010000"),
                                 Certificate.fromIsoString("20150825T040000"));
    // Right in interval1, there's an intersection.
    var interval5 = new Interval(Certificate.fromIsoString("20150825T030000"),
                                 Certificate.fromIsoString("20150825T040000"));
    // Wrap interval1, there's an intersection.
    var interval6 = new Interval(Certificate.fromIsoString("20150825T010000"),
                                 Certificate.fromIsoString("20150825T050000"));
    // Empty interval.
    var interval7 = new Interval(true);

    var tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval2);
    assert.ok(tempInterval.isEmpty());

    tempInterval = new Interval(interval1);
    var gotError = true;
    try {
      tempInterval.unionWith(interval2);
      gotError = false;
    } catch (ex) {}
    if (!gotError)
      fail("Expected error in unionWith(interval2)");

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval3);
    assert.ok(tempInterval.isEmpty());

    tempInterval = new Interval(interval1);
    gotError = true;
    try {
      tempInterval.unionWith(interval3);
      gotError = false;
    } catch (ex) {}
    if (!gotError)
      fail("Expected error in unionWith(interval3)");

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval4);
    assert.ok(!tempInterval.isEmpty());
    assert.ok("20150825T030000" == Certificate.toIsoString(tempInterval.getStartTime()));
    assert.ok("20150825T040000" == Certificate.toIsoString(tempInterval.getEndTime()));

    tempInterval = new Interval(interval1);
    tempInterval.unionWith(interval4);
    assert.ok(!tempInterval.isEmpty());
    assert.ok("20150825T010000" == Certificate.toIsoString(tempInterval.getStartTime()));
    assert.ok("20150825T050000" == Certificate.toIsoString(tempInterval.getEndTime()));

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval5);
    assert.ok(!tempInterval.isEmpty());
    assert.ok("20150825T030000" == Certificate.toIsoString(tempInterval.getStartTime()));
    assert.ok("20150825T040000" == Certificate.toIsoString(tempInterval.getEndTime()));

    tempInterval = new Interval(interval1);
    tempInterval.unionWith(interval5);
    assert.ok(!tempInterval.isEmpty());
    assert.ok("20150825T030000" == Certificate.toIsoString(tempInterval.getStartTime()));
    assert.ok("20150825T050000" == Certificate.toIsoString(tempInterval.getEndTime()));

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval6);
    assert.ok(!tempInterval.isEmpty());
    assert.ok("20150825T030000" == Certificate.toIsoString(tempInterval.getStartTime()));
    assert.ok("20150825T050000" == Certificate.toIsoString(tempInterval.getEndTime()));

    tempInterval = new Interval(interval1);
    tempInterval.unionWith(interval6);
    assert.ok(!tempInterval.isEmpty());
    assert.ok("20150825T010000" == Certificate.toIsoString(tempInterval.getStartTime()));
    assert.ok("20150825T050000" == Certificate.toIsoString(tempInterval.getEndTime()));

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval7);
    assert.ok(tempInterval.isEmpty());

    tempInterval = new Interval(interval1);
    tempInterval.unionWith(interval7);
    assert.ok(!tempInterval.isEmpty());
    assert.ok("20150825T030000" == Certificate.toIsoString(tempInterval.getStartTime()));
    assert.ok("20150825T050000" == Certificate.toIsoString(tempInterval.getEndTime()));
  });
});

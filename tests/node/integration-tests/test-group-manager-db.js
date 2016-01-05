/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/group-manager-db.t.cpp
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
var fs = require("fs");
var Blob = require('../../..').Blob;
var Name = require('../../..').Name;
var RepetitiveInterval = require('../../..').RepetitiveInterval;
var Schedule = require('../../..').Schedule;
var RsaKeyParams = require('../../..').RsaKeyParams;
var RsaAlgorithm = require('../../..').RsaAlgorithm;
var Sqlite3GroupManagerDb = require('../../..').Sqlite3GroupManagerDb;
var Common = require('../unit-tests/unit-tests-common.js').UnitTestsCommon;

var SCHEDULE = new Buffer([
  0x8f, 0xc4,// Schedule
  0x8d, 0x90,// WhiteIntervalList
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x04,
    0x89, 0x01,
      0x07,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00,
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x05,
    0x89, 0x01,
      0x0a,
    0x8a, 0x01,
      0x02,
    0x8b, 0x01,
      0x01,
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x06,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x01,
    0x8b, 0x01,
      0x01,
  0x8e, 0x30, // BlackIntervalList
  0x8c, 0x2e, // RepetitiveInterval
     0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x07,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00
]);

var databaseFilePath;
var database;

describe ("TestGroupManagerDb", function() {
  beforeEach(function(done) {
    databaseFilePath = "policy_config/test.db";
    try {
      fs.unlinkSync(databaseFilePath);
    }
    catch (e) {}

    database = new Sqlite3GroupManagerDb(databaseFilePath);
    done();
  });

  afterEach(function(done) {
    try {
      fs.unlinkSync(databaseFilePath);
    }
    catch (e) {}

    done();
  });

  it("DatabaseFunctions", function(done) {
    var newSchedule;
    var scheduleBlob = new Blob(SCHEDULE, false);

    // Create a schedule.
    var schedule = new Schedule();
    schedule.wireDecode(scheduleBlob);

    // Create a member.
    var params = new RsaKeyParams();
    var encryptKey;
    var keyBlob;
    var name1;
    var name2;
    var name3;
    var name4;
    var name5;

    RsaAlgorithm.generateKeyPromise(params)
    .then(function(decryptKey) {
      encryptKey = RsaAlgorithm.deriveEncryptKey(decryptKey.getKeyBits());
      keyBlob = encryptKey.getKeyBits();

      name1 = new Name("/ndn/BoyA/ksk-123");
      name2 = new Name("/ndn/BoyB/ksk-1233");
      name3 = new Name("/ndn/GirlC/ksk-123");
      name4 = new Name("/ndn/GirlD/ksk-123");
      name5 = new Name("/ndn/Hello/ksk-123");

      // Add schedules into the database.
      return database.addSchedulePromise("work-time", schedule);
    })
    .then(function() {
      return database.addSchedulePromise("rest-time", schedule);
    })
    .then(function() {
      return database.addSchedulePromise("play-time", schedule);
    })
    .then(function() {
      return database.addSchedulePromise("boelter-time", schedule);
    })
    .then(function() {
      // Get an error when adding a schedule with an existing name.
      return database.addSchedulePromise("boelter-time", schedule)
      .then(function() {
        assert.fail('', '', "Expected an error adding a duplicate schedule");
      }, function(err) {
        // Got the expected error.
        return Promise.resolve();
      });
    })
    .then(function() {
      // Add members into the database.
      return database.addMemberPromise("work-time", name1, keyBlob);
    })
    .then(function() {
      // Add members into the database.
      return database.addMemberPromise("rest-time", name2, keyBlob);
    })
    .then(function() {
      // Add members into the database.
      return database.addMemberPromise("play-time", name3, keyBlob);
    })
    .then(function() {
      // Add members into the database.
      return database.addMemberPromise("play-time", name4, keyBlob);
    })
    .then(function() {
      // Get an error when adding a member with a non-existing schedule name.
      return database.addMemberPromise("false-time", name5, keyBlob)
      .then(function() {
        assert.fail('', '', "Expected an error adding a member with non-existing schedule");
      }, function(err) {
        // Got the expected error.
        return Promise.resolve();
      });
    })
    .then(function() {
      // Add members into the database.
      return database.addMemberPromise("boelter-time", name5, keyBlob);
    })
    .then(function() {
      // Get an error when adding a member having an existing identity.
      return database.addMemberPromise("work-time", name5, keyBlob)
      .then(function() {
        assert.fail('', '', "Expected an error adding a member with an existing identity");
      }, function(err) {
        // Got the expected error.
        return Promise.resolve();
      });
    })
    .then(function() {
      return database.hasSchedulePromise("work-time");
    })
    .then(function(hasSchedule) {
      assert.equal(hasSchedule, true);
      return database.hasSchedulePromise("rest-time");
    })
    .then(function(hasSchedule) {
      assert.equal(hasSchedule, true);
      return database.hasSchedulePromise("play-time");
    })
    .then(function(hasSchedule) {
      assert.equal(hasSchedule, true);
      return database.hasSchedulePromise("sleep-time");
    })
    .then(function(hasSchedule) {
      assert.equal(hasSchedule, false);
      return database.hasSchedulePromise("");
    })
    .then(function(hasSchedule) {
      assert.equal(hasSchedule, false);

      return database.hasMemberPromise(new Name("/ndn/BoyA"));
    })
    .then(function(hasMember) {
      assert.equal(hasMember, true);
      return database.hasMemberPromise(new Name("/ndn/BoyB"));
    })
    .then(function(hasMember) {
      assert.equal(hasMember, true);
      return database.hasMemberPromise(new Name("/ndn/BoyC"));
    })
    .then(function(hasMember) {
      assert.equal(hasMember, false);

      // Get a schedule.
      return database.getSchedulePromise("work-time");
    })
    .then(function(scheduleResult) {
      assert.ok(scheduleResult.wireEncode().equals(scheduleBlob));
      return database.getSchedulePromise("play-time");
    })
    .then(function(scheduleResult) {
      assert.ok(scheduleResult.wireEncode().equals(scheduleBlob));

      // Get an error when when there is no such schedule in the database.
      return database.getSchedulePromise("work-time-11")
      .then(function() {
        assert.fail('', '', "Expected an error getting a non-existing schedule");
      }, function(err) {
        // Got the expected error.
        return Promise.resolve();
      });
    })
    .then(function() {
      // List all schedule names.
      return database.listAllScheduleNamesPromise()
    })
    .then(function(names) {
      assert.ok(names.indexOf("work-time") >= 0);
      assert.ok(names.indexOf("play-time") >= 0);
      assert.ok(names.indexOf("rest-time") >= 0);
      assert.ok(names.indexOf("sleep-time") < 0);

      // List members of a schedule.
      return database.getScheduleMembersPromise("play-time");
    })
    .then(function(memberList) {
      assert.ok(memberList.length != 0);

      // When there's no such schedule, the returned list's size should be 0.
      return database.getScheduleMembersPromise("sleep-time");
    })
    .then(function(memberList) {
      assert.equal(memberList.length, 0);

      // List all members.
      return database.listAllMembersPromise();
    })
    .then(function(members) {
      assert.ok(members.some(function(x) { return x.equals(new Name("/ndn/GirlC")); }));
      assert.ok(members.some(function(x) { return x.equals(new Name("/ndn/GirlD")); }));
      assert.ok(members.some(function(x) { return x.equals(new Name("/ndn/BoyA")); }));
      assert.ok(members.some(function(x) { return x.equals(new Name("/ndn/BoyB")); }));

      // Rename a schedule.
      return database.hasSchedulePromise("boelter-time");
    })
    .then(function(hasSchedule) {
      assert.equal(hasSchedule, true);
      return database.renameSchedulePromise("boelter-time", "rieber-time");
    })
    .then(function() {
      return database.hasSchedulePromise("boelter-time");
    })
    .then(function(hasSchedule) {
      assert.equal(hasSchedule, false);
      return database.hasSchedulePromise("rieber-time");
    })
    .then(function(hasSchedule) {
      assert.equal(hasSchedule, true);
      return database.getMemberSchedulePromise(new Name("/ndn/Hello"));
    })
    .then(function(scheduleName) {
      assert.equal(scheduleName, "rieber-time");

      // Update a schedule.
      newSchedule = new Schedule();
      newSchedule.wireDecode(scheduleBlob);
      var repetitiveInterval = new RepetitiveInterval
        (Common.fromIsoString("20150825T000000"),
         Common.fromIsoString("20150921T000000"), 2, 10,
         5, RepetitiveInterval.RepeatUnit.DAY);
      newSchedule.addWhiteInterval(repetitiveInterval);
      return database.updateSchedulePromise("rieber-time", newSchedule);
    })
    .then(function() {
      return database.getSchedulePromise("rieber-time");
    })
    .then(function(scheduleResult) {
      assert.ok(!scheduleResult.wireEncode().equals(scheduleBlob));
      assert.ok(scheduleResult.wireEncode().equals(newSchedule.wireEncode()));

      // Add a new schedule when updating a non-existing schedule.
      return database.hasSchedulePromise("ralphs-time");
    })
    .then(function(hasSchedule) {
      assert.equal(hasSchedule, false);
      return database.updateSchedulePromise("ralphs-time", newSchedule);
    })
    .then(function() {
      return database.hasSchedulePromise("ralphs-time");
    })
    .then(function(hasSchedule) {
      assert.equal(hasSchedule, true);

      // Update the schedule of a member.
      return database.updateMemberSchedulePromise
        (new Name("/ndn/Hello"), "play-time");
    })
    .then(function() {
      return database.getMemberSchedulePromise(new Name("/ndn/Hello"));
    })
    .then(function(scheduleName) {
      assert.equal(scheduleName, "play-time");

      // Delete a member.
      return database.hasMemberPromise(new Name("/ndn/Hello"));
    })
    .then(function(hasMember) {
      assert.equal(hasMember, true);
      return database.deleteMemberPromise(new Name("/ndn/Hello"));
    })
    .then(function() {
      return database.hasMemberPromise(new Name("/ndn/Hello"));
    })
    .then(function(hasMember) {
      assert.equal(hasMember, false);

      // Delete a non-existing member.
      return database.deleteMemberPromise(new Name("/ndn/notExisting"))
      .then(function() {
        // No error, as expected.
        return Promise.resolve();
      }, function(err) {
        assert.fail('', '', "Unexpected error deleting a non-existing member: " + err);
      });
    })
    .then(function() {
      // Delete a schedule. All the members using this schedule should be deleted.
      return database.deleteSchedulePromise("play-time");
    })
    .then(function() {
      return database.hasSchedulePromise("play-time");
    })
    .then(function(hasSchedule) {
      assert.equal(hasSchedule, false);
      return database.hasMemberPromise(new Name("/ndn/GirlC"));
    })
    .then(function(hasMember) {
      assert.equal(hasMember, false);
      return database.hasMemberPromise(new Name("/ndn/GirlD"));
    })
    .then(function(hasMember) {
      assert.equal(hasMember, false);

      // Delete a non-existing schedule.
      return database.deleteSchedulePromise("not-existing-time")
      .then(function() {
        // No error, as expected.
        return Promise.resolve();
      }, function(err) {
        assert.fail('', '', "Unexpected error deleting a non-existing schedule: " + err);
      });
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });
});

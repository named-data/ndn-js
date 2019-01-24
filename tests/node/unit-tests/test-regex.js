/**
 * Copyright (C) 2014-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx Regex unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/util/regex.t.cpp
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
var NdnRegexBackrefManager = require('../../../js/util/regex/ndn-regex-backref-manager.js').NdnRegexBackrefManager;
var NdnRegexMatcherBase = require('../../../js/util/regex/ndn-regex-matcher-base.js').NdnRegexMatcherBase;
var NdnRegexComponentMatcher = require('../../../js/util/regex/ndn-regex-component-matcher.js').NdnRegexComponentMatcher;
var NdnRegexComponentSetMatcher = require('../../../js/util/regex/ndn-regex-component-set-matcher.js').NdnRegexComponentSetMatcher;
var NdnRegexRepeatMatcher = require('../../../js/util/regex/ndn-regex-repeat-matcher.js').NdnRegexRepeatMatcher;
var NdnRegexBackrefMatcher = require('../../../js/util/regex/ndn-regex-backref-matcher.js').NdnRegexBackrefMatcher;
var NdnRegexPatternListMatcher = require('../../../js/util/regex/ndn-regex-pattern-list-matcher.js').NdnRegexPatternListMatcher;
var NdnRegexTopMatcher = require('../../../js/util/regex/ndn-regex-top-matcher.js').NdnRegexTopMatcher;

describe('TestRegex', function() {
  it('ComponentMatcher', function() {
    var backRef = new NdnRegexBackrefManager();
    var cm = new NdnRegexComponentMatcher("a", backRef);
    var res = cm.match(new Name("/a/b/"), 0, 1);
    assert.equal(true, res);
    assert.equal(1, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexComponentMatcher("a", backRef);
    res = cm.match(new Name("/a/b/"), 1, 1);
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexComponentMatcher("(c+)\\.(cd)", backRef);
    res = cm.match(new Name("/ccc.cd/b/"), 0, 1);
    assert.equal(true, res);
    assert.equal(1, cm.getMatchResult().length);
    assert.equal("ccc.cd", cm.getMatchResult()[0].toEscapedString());

    assert.equal(2, backRef.size());
    assert.equal("ccc",
      backRef.getBackref(0).getMatchResult()[0].toEscapedString());
    assert.equal("cd",
      backRef.getBackref(1).getMatchResult()[0].toEscapedString());
  });

  it('ComponentSetMatcher', function() {
    var backRef = new NdnRegexBackrefManager();
    var cm = new NdnRegexComponentSetMatcher("<a>", backRef);
    var res = cm.match(new Name("/a/b/"), 0, 1);
    assert.equal(true, res);
    assert.equal(1, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());

    res = cm.match(new Name("/a/b/"), 1, 1);
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    res = cm.match(new Name("/a/b/"), 0, 2);
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexComponentSetMatcher("[<a><b><c>]", backRef);
    res = cm.match(new Name("/a/b/d"), 1, 1);
    assert.equal(true, res);
    assert.equal(1, cm.getMatchResult().length);
    assert.equal("b", cm.getMatchResult()[0].toEscapedString());

    res = cm.match(new Name("/a/b/d"), 2, 1);
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexComponentSetMatcher("[^<a><b><c>]", backRef);
    res = cm.match(new Name("/b/d"), 1, 1);
    assert.equal(true, res);
    assert.equal(1, cm.getMatchResult().length);
    assert.equal("d", cm.getMatchResult()[0].toEscapedString());

    backRef = new NdnRegexBackrefManager();
    assert.throws
      (function() { new NdnRegexComponentSetMatcher("[<a]", backRef); },
       NdnRegexMatcherBase.Error);
  });

  it('RepeatMatcher', function() {
    var backRef = new NdnRegexBackrefManager();
    var cm = new NdnRegexRepeatMatcher("[<a><b>]*", backRef, 8);
    var res = cm.match(new Name("/a/b/c"), 0, 0);
    assert.equal(true, res);
    assert.equal(0, cm.getMatchResult().length);

    res = cm.match(new Name("/a/b/c"), 0, 2);
    assert.equal(true, res);
    assert.equal(2, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("[<a><b>]+", backRef, 8);
    res = cm.match(new Name("/a/b/c"), 0, 0);
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    res = cm.match(new Name("/a/b/c"), 0, 2);
    assert.equal(true, res);
    assert.equal(2, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("<.*>*", backRef, 4);
    res = cm.match(new Name("/a/b/c/d/e/f/"), 0, 6);
    assert.equal(true, res);
    assert.equal(6, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal("c", cm.getMatchResult()[2].toEscapedString());
    assert.equal("d", cm.getMatchResult()[3].toEscapedString());
    assert.equal("e", cm.getMatchResult()[4].toEscapedString());
    assert.equal("f", cm.getMatchResult()[5].toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("<>*", backRef, 2);
    res = cm.match(new Name("/a/b/c/d/e/f/"), 0, 6);
    assert.equal(true, res);
    assert.equal(6, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal("c", cm.getMatchResult()[2].toEscapedString());
    assert.equal("d", cm.getMatchResult()[3].toEscapedString());
    assert.equal("e", cm.getMatchResult()[4].toEscapedString());
    assert.equal("f", cm.getMatchResult()[5].toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("<a>?", backRef, 3);
    res = cm.match(new Name("/a/b/c"), 0, 0);
    assert.equal(true, res);
    assert.equal(0, cm.getMatchResult().length);

    cm = new NdnRegexRepeatMatcher("<a>?", backRef, 3);
    res = cm.match(new Name("/a/b/c"), 0, 1);
    assert.equal(true, res);
    assert.equal(1, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());

    cm = new NdnRegexRepeatMatcher("<a>?", backRef, 3);
    res = cm.match(new Name("/a/b/c"), 0, 2);
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("[<a><b>]{3}", backRef, 8);
    res = cm.match(new Name("/a/b/a/d/"), 0, 2);
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    res = cm.match(new Name("/a/b/a/d/"), 0, 3);
    assert.equal(true, res);
    assert.equal(3, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal("a", cm.getMatchResult()[2].toEscapedString());

    res = cm.match(new Name("/a/b/a/d/"), 0, 4);
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("[<a><b>]{2,3}", backRef, 8);
    res = cm.match(new Name("/a/b/a/d/e/"), 0, 2);
    assert.equal(true, res);
    assert.equal(2, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());

    res = cm.match(new Name("/a/b/a/d/e/"), 0, 3);
    assert.equal(true, res);
    assert.equal(3, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal("a", cm.getMatchResult()[2].toEscapedString());

    res = cm.match(new Name("/a/b/a/b/e/"), 0, 4);
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    res = cm.match(new Name("/a/b/a/d/e/"), 0, 1);
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("[<a><b>]{2,}", backRef, 8);
    res = cm.match(new Name("/a/b/a/d/e/"), 0, 2);
    assert.equal(true, res);
    assert.equal(2, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());

    res = cm.match(new Name("/a/b/a/b/e/"), 0, 4);
    assert.equal(true, res);
    assert.equal(4, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal("a", cm.getMatchResult()[2].toEscapedString());
    assert.equal("b", cm.getMatchResult()[3].toEscapedString());

    res = cm.match(new Name("/a/b/a/d/e/"), 0, 1);
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("[<a><b>]{,2}", backRef, 8);
    res = cm.match(new Name("/a/b/a/b/e/"), 0, 3);
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    res = cm.match(new Name("/a/b/a/b/e/"), 0, 2);
    assert.equal(true, res);
    assert.equal(2, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());

    res = cm.match(new Name("/a/b/a/d/e/"), 0, 1);
    assert.equal(true, res);
    assert.equal(1, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());

    res = cm.match(new Name("/a/b/a/d/e/"), 0, 0);
    assert.equal(true, res);
    assert.equal(0, cm.getMatchResult().length);
  });

  it('BackrefMatcher', function() {
    var backRef = new NdnRegexBackrefManager();
    var cm = new NdnRegexBackrefMatcher("(<a><b>)", backRef);
    backRef.pushRef(cm);
    cm.lateCompile();
    var res = cm.match(new Name("/a/b/c"), 0, 2);
    assert.equal(true, res);
    assert.equal(2, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal(1, backRef.size());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexBackrefMatcher("(<a>(<b>))", backRef);
    backRef.pushRef(cm);
    cm.lateCompile();
    res = cm.match(new Name("/a/b/c"), 0, 2);
    assert.equal(true, res);
    assert.equal(2, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal(2, backRef.size());
    assert.equal("a",
      backRef.getBackref(0).getMatchResult()[0].toEscapedString());
    assert.equal("b",
      backRef.getBackref(0).getMatchResult()[1].toEscapedString());
    assert.equal("b",
      backRef.getBackref(1).getMatchResult()[0].toEscapedString());
  });

  it('BackrefMatcherAdvanced', function() {
    var backRef = new NdnRegexBackrefManager();
    var cm = new NdnRegexRepeatMatcher("([<a><b>])+", backRef, 10);
    var res = cm.match(new Name("/a/b/c"), 0, 2);
    assert.equal(true, res);
    assert.equal(2, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal(1, backRef.size());
    assert.equal("b",
      backRef.getBackref(0).getMatchResult()[0].toEscapedString());
  });

  it('BackrefMatcherAdvanced2', function() {
    var backRef = new NdnRegexBackrefManager();
    var cm = new NdnRegexPatternListMatcher("(<a>(<b>))<c>", backRef);
    var res = cm.match(new Name("/a/b/c"), 0, 3);
    assert.equal(true, res);
    assert.equal(3, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal("c", cm.getMatchResult()[2].toEscapedString());
    assert.equal(2, backRef.size());
    assert.equal("a",
      backRef.getBackref(0).getMatchResult()[0].toEscapedString());
    assert.equal("b",
      backRef.getBackref(0).getMatchResult()[1].toEscapedString());
    assert.equal("b",
      backRef.getBackref(1).getMatchResult()[0].toEscapedString());
  });

  it('PatternListMatcher', function() {
    var backRef = new NdnRegexBackrefManager();
    var cm = new NdnRegexPatternListMatcher("<a>[<a><b>]", backRef);
    var res = cm.match(new Name("/a/b/c"), 0, 2);
    assert.equal(true, res);
    assert.equal(2, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexPatternListMatcher("<>*<a>", backRef);
    res = cm.match(new Name("/a/b/c"), 0, 1);
    assert.equal(true, res);
    assert.equal(1, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexPatternListMatcher("<>*<a>", backRef);
    res = cm.match(new Name("/a/b/c"), 0, 2);
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexPatternListMatcher("<>*<a><>*", backRef);
    res = cm.match(new Name("/a/b/c"), 0, 3);
    assert.equal(true, res);
    assert.equal(3, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal("c", cm.getMatchResult()[2].toEscapedString());
  });

  it('TopMatcher', function() {
    var cm = new NdnRegexTopMatcher("^<a><b><c>");
    var res = cm.match(new Name("/a/b/c/d"));
    assert.equal(true, res);
    assert.equal(4, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal("c", cm.getMatchResult()[2].toEscapedString());
    assert.equal("d", cm.getMatchResult()[3].toEscapedString());

    cm = new NdnRegexTopMatcher("<b><c><d>$");
    res = cm.match(new Name("/a/b/c/d"));
    assert.equal(true, res);
    assert.equal(4, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal("c", cm.getMatchResult()[2].toEscapedString());
    assert.equal("d", cm.getMatchResult()[3].toEscapedString());

    cm = new NdnRegexTopMatcher("^<a><b><c><d>$");
    res = cm.match(new Name("/a/b/c/d"));
    assert.equal(true, res);
    assert.equal(4, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal("c", cm.getMatchResult()[2].toEscapedString());
    assert.equal("d", cm.getMatchResult()[3].toEscapedString());

    res = cm.match(new Name("/a/b/c/d/e"));
    assert.equal(false, res);
    assert.equal(0, cm.getMatchResult().length);

    cm = new NdnRegexTopMatcher("<a><b><c><d>");
    res = cm.match(new Name("/a/b/c/d"));
    assert.equal(true, res);
    assert.equal(4, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal("c", cm.getMatchResult()[2].toEscapedString());
    assert.equal("d", cm.getMatchResult()[3].toEscapedString());

    cm = new NdnRegexTopMatcher("<b><c>");
    res = cm.match(new Name("/a/b/c/d"));
    assert.equal(true, res);
    assert.equal(4, cm.getMatchResult().length);
    assert.equal("a", cm.getMatchResult()[0].toEscapedString());
    assert.equal("b", cm.getMatchResult()[1].toEscapedString());
    assert.equal("c", cm.getMatchResult()[2].toEscapedString());
    assert.equal("d", cm.getMatchResult()[3].toEscapedString());
  });

  it('TopMatcherAdvanced', function() {
    var cm = new NdnRegexTopMatcher("^(<.*>*)<.*>");
    var res = cm.match(new Name("/n/a/b/c"));
    assert.equal(true, res);
    assert.equal(4, cm.getMatchResult().length);
    assert.ok(new Name("/n/a/b/").equals(cm.expand("\\1")));

    cm = new NdnRegexTopMatcher("^(<.*>*)<.*><c>(<.*>)<.*>");
    res = cm.match(new Name("/n/a/b/c/d/e/"));
    assert.equal(true, res);
    assert.equal(6, cm.getMatchResult().length);
    assert.ok(new Name("/n/a/d/").equals(cm.expand("\\1\\2")));

    cm = new NdnRegexTopMatcher("(<.*>*)<.*>$");
    res = cm.match(new Name("/n/a/b/c/"));
    assert.equal(true, res);
    assert.equal(4, cm.getMatchResult().length);
    assert.ok(new Name("/n/a/b/").equals(cm.expand("\\1")));

    cm = new NdnRegexTopMatcher("<.*>(<.*>*)<.*>$");
    res = cm.match(new Name("/n/a/b/c/"));
    assert.equal(true, res);
    assert.equal(4, cm.getMatchResult().length);
    assert.ok(new Name("/a/b/").equals(cm.expand("\\1")));

    cm = new NdnRegexTopMatcher("<a>(<>*)<>$");
    res = cm.match(new Name("/n/a/b/c/"));
    assert.equal(true, res);
    assert.equal(4, cm.getMatchResult().length);
    assert.ok(new Name("/b/").equals(cm.expand("\\1")));

    cm = new NdnRegexTopMatcher("^<ndn><(.*)\\.(.*)><DNS>(<>*)<>");
    res = cm.match(new Name("/ndn/ucla.edu/DNS/yingdi/mac/ksk-1/"));
    assert.equal(true, res);
    assert.equal(6, cm.getMatchResult().length);
    assert.ok(new Name("/ndn/edu/ucla/yingdi/mac/").equals
              (cm.expand("<ndn>\\2\\1\\3")));

    cm = new NdnRegexTopMatcher
      ("^<ndn><(.*)\\.(.*)><DNS>(<>*)<>", "<ndn>\\2\\1\\3");
    res = cm.match(new Name("/ndn/ucla.edu/DNS/yingdi/mac/ksk-1/"));
    assert.equal(true, res);
    assert.equal(6, cm.getMatchResult().length);
    assert.ok(new Name("/ndn/edu/ucla/yingdi/mac/").equals(cm.expand()));
  });
});

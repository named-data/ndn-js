/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
  * From PyNDN boost_info_parser by Adeola Bannis.
*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
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

var fs = require('fs');

var BoostInfoTree = function BoostInfoTree(value, parent)
{
  this.value = value;
  this.parent = parent;
  // subTrees is an array of {key: treeName, value: subTreeList} where
  // treeName is a string and subTreeList is an array of BoostInfoTree.
  this.subTrees = [];
  this.lastChild = null;
};

BoostInfoTree.prototype.createSubtree = function(treeName, value)
{
  var newTree = new BoostInfoTree(value, this);

  var subTreeList = this.find(treeName);
  if (subTreeList !== null)
    this.subTreeList.push(newTree);
  else
    this.subTrees.push({key: treeName, value: [newTree]});

  this.lastChild = newTree;
};

BoostInfoTree.prototype.getValue = function() { return this.value; };

BoostInfoTree.prototype.getParent = function() { return this.parent; };

BoostInfoTree.prototype.getLastChild = function() { return this.lastChild; };

BoostInfoTree.prototype.prettyPrint = function(indentLevel)
{
  indentLevel = indentLevel || 1;

  var prefix = Array(indentLevel + 1).join(' ');
  var s = "";

  if (this.parent != null) {
    if (this.value && this.value.length > 0)
      s += "\"" + this.value + "\"";
    s += "\n";
  }

  if (this.subTrees.length > 0) {
    if (this.parent)
      s += prefix + "{\n";
    var nextLevel = Array(indentLevel + 2 + 1).join(' ');
    for (var i = 0; i < this.subTrees.length; ++i) {
      for (var iSubTree = 0; iSubTree < this.subTrees[i].value.length; ++iSubTree)
        s += nextLevel + this.subTrees[i].key + " " +
             this.subTrees[i].value[iSubTree].prettyPrint(indentLevel + 2);
    }

    if (this.parent)
      s +=  prefix + "}\n";
  }

  return s;
};

BoostInfoTree.prototype.toString = function()
{
  return this.prettyPrint();
}

/**
 * Use treeName to find the array of BoostInfoTree in this.subTrees.
 * @param {string} treeName The key in this.subTrees to search for.
 * @returns {Array<BoostInfoTree>} A array of BoostInfoTree, or null if not found.
 */
BoostInfoTree.prototype.find = function(treeName)
{
  for (var i = 0; i < this.subTrees.length; ++i) {
    if (this.subTrees[i].key == treeName)
      return this.subTrees[i].value;
  }

  return null;
};

var BoostInfoParser = function BoostInfoParser()
{
  this.root = new BoostInfoTree();
};

exports.BoostInfoParser = BoostInfoParser;

BoostInfoParser.prototype.read = function(fileName)
{
  var ctx = this.root;
  var thisParser = this;
  fs.readFileSync(fileName).toString().split(/\r?\n/).forEach(function(line) {
    ctx = thisParser.parseLine(line.trim(), ctx);
  });
};

BoostInfoParser.prototype.write = function(fileName)
{
  fs.writeFileSync(fileName, "" + this.root);
};

BoostInfoParser.prototype.getRoot = function() { return this.root; };

/**
 * Similar to Python's shlex.split, split s into an array of strings which are
 * separated by whitespace, treating a string within quotes as a single entity
 * regardless of whitespace between the quotes. Also allow a backslash to escape
 * the next character.
 * @param {string} s The input string to split.
 * @returns {Array<string>} An array of strings.
 */
BoostInfoParser.shlex_split = function(s)
{
  var result = [];
  if (s == "")
    return result;
  var whiteSpace = " \t\n\r";
  var iStart = 0;

  while (true) {
    // Move iStart past whitespace.
    while (whiteSpace.indexOf(s[iStart]) >= 0) {
      iStart += 1;
      if (iStart >= s.length)
        // Done.
        return result;
    }

    // Move iEnd to the end of the token.
    var iEnd = iStart;
    var inQuotation = false;
    var token = "";
    while (true) {
      if (s[iEnd] == '\\') {
        // Append characters up to the backslash, skip the backslash and
        //   move iEnd past the escaped character.
        token += s.substring(iStart, iEnd);
        iStart = iEnd + 1;
        iEnd = iStart;
        if (iEnd >= s.length)
          // An unusual case: A backslash at the end of the string.
          break;
      }
      else {
        if (inQuotation) {
          if (s[iEnd] == '\"') {
            // Append characters up to the end quote and skip.
            token += s.substring(iStart, iEnd);
            iStart = iEnd + 1;
            inQuotation = false;
          }
        }
        else {
          if (s[iEnd] == '\"') {
            // Append characters up to the start quote and skip.
            token += s.substring(iStart, iEnd);
            iStart = iEnd + 1;
            inQuotation = true;
          }
          else
            if (whiteSpace.indexOf(s[iEnd]) >= 0)
              break;
        }
      }

      iEnd += 1;
      if (iEnd >= s.length)
        break;
    }

    token += s.substring(iStart, iEnd);
    result.push(token);
    if (iEnd >= s.length)
      // Done.
      return result;

    iStart = iEnd;
  }
};

BoostInfoParser.prototype.parseLine = function(line, context)
{
  // Skip blank lines and comments.
  var commentStart = line.indexOf(';');
  if (commentStart >= 0)
    line = line.substring(0, commentStart).trim();
  if (line.length == 0)
    return context;

  // Usually we are expecting key and optional value.
  var strings = BoostInfoParser.shlex_split(line);
  var isSectionStart = false;
  var isSectionEnd = false;
  for (var i = 0; i < strings.length; ++i) {
    isSectionStart = (isSectionStart || strings[i] == "{");
    isSectionEnd = (isSectionEnd || strings[i] == "}");
  }

  if (!isSectionStart && !isSectionEnd) {
    var key = strings[0];
    var val;
    if (strings.length > 1)
      val = strings[1];
    context.createSubtree(key, val);

    return context;
  }

  // OK, who is the joker who put a { on the same line as the key name?!
  var sectionStart = line.indexOf('{');
  if (sectionStart > 0) {
    var firstPart = line.substring(0, sectionStart);
    var secondPart = line.substring(sectionStart);

    var ctx = this.parseLine(firstPart, context);
    return this.parseLine(secondPart, ctx);
  }

  // If we encounter a {, we are beginning a new context.
  // TODO: Error if there was already a subcontext here.
  if (line[0] == '{') {
    context = context.getLastChild();
    return context;
  }

  // If we encounter a }, we are ending a list context.
  if (line[0] == '}') {
    context = context.getParent();
    return context;
  }

  throw runtime_error("BoostInfoParser: input line is malformed");
};

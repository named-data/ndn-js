/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From PyNDN der.py by Adeola Bannis <thecodemaiden@gmail.com>.
 * @author: Originally from code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
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

/**
 * The NodeType enum defines the known DER node types.
 */
var NodeType = function NodeType()
{
}

exports.NodeType = NodeType;

NodeType.Eoc = 0;
NodeType.Boolean = 1;
NodeType.Integer = 2;
NodeType.BitString = 3;
NodeType.OctetString = 4;
NodeType.Null = 5;
NodeType.ObjectIdentifier = 6;
NodeType.ObjectDescriptor = 7;
NodeType.External = 40;
NodeType.Real = 9;
NodeType.Enumerated = 10;
NodeType.EmbeddedPdv = 43;
NodeType.Utf8String = 12;
NodeType.RelativeOid = 13;
NodeType.Sequence = 48;
NodeType.Set = 49;
NodeType.NumericString = 18;
NodeType.PrintableString = 19;
NodeType.T61String = 20;
NodeType.VideoTexString = 21;
NodeType.Ia5String = 22;
NodeType.UtcTime = 23;
NodeType.GeneralizedTime = 24;
NodeType.GraphicString = 25;
NodeType.VisibleString = 26;
NodeType.GeneralString = 27;
NodeType.UniversalString = 28;
NodeType.CharacterString = 29;
NodeType.BmpString = 30;

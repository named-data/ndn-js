/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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
 * The DerNodeType enum defines the known DER node types.
 */
var DerNodeType = function DerNodeType()
{
}

exports.DerNodeType = DerNodeType;

DerNodeType.Eoc = 0;
DerNodeType.Boolean = 1;
DerNodeType.Integer = 2;
DerNodeType.BitString = 3;
DerNodeType.OctetString = 4;
DerNodeType.Null = 5;
DerNodeType.ObjectIdentifier = 6;
DerNodeType.ObjectDescriptor = 7;
DerNodeType.External = 40;
DerNodeType.Real = 9;
DerNodeType.Enumerated = 10;
DerNodeType.EmbeddedPdv = 43;
DerNodeType.Utf8String = 12;
DerNodeType.RelativeOid = 13;
DerNodeType.Sequence = 48;
DerNodeType.Set = 49;
DerNodeType.NumericString = 18;
DerNodeType.PrintableString = 19;
DerNodeType.T61String = 20;
DerNodeType.VideoTexString = 21;
DerNodeType.Ia5String = 22;
DerNodeType.UtcTime = 23;
DerNodeType.GeneralizedTime = 24;
DerNodeType.GraphicString = 25;
DerNodeType.VisibleString = 26;
DerNodeType.GeneralString = 27;
DerNodeType.UniversalString = 28;
DerNodeType.CharacterString = 29;
DerNodeType.BmpString = 30;

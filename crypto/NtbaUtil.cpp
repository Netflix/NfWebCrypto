/*
 *
 *  Copyright 2013 Netflix, Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */
#include "NtbaUtil.h"
#include <fstream>
#include <iostream>
#include <locale>
#include <sstream>
#include <stdio.h>
#include <string>
#include <unistd.h>
#include <base/ScopedMutex.h>

#if 0
#include "Env.h"
#endif

namespace cadmium {
namespace crypto {

std::string NtbaUtil::toBinaryString(unsigned char c)
{
    std::string bin;
    // deal with Java's lack of unsigned types by masking bit 8 first
    unsigned char mask = 0x80; // 1000 0000
    while(mask > 0) {
        bin += (c & mask) != 0 ? "1" : "0";
        mask >>= 1;
    }
    return bin;
}

bool NtbaUtil::isPowerOf2(unsigned int i)
{
    if(i == 0) { return false; }
    return ((i & (i - 1)) == 0);
}

std::string NtbaUtil::toFormatHexString
    (const std::vector<unsigned char> &data, const std::string &name, size_t width,
     size_t indent_level, const std::string &delim, size_t indent_len)
{
    return toFormatHexString(&data[0], data.size(), name, width,
                             indent_level, delim, indent_len);
}

std::string NtbaUtil::toFormatHexString
    (const unsigned char *data, size_t len, const std::string &name, size_t width,
     size_t indent_level, const std::string &delim, size_t indent_len)
{
    std::ostringstream ostr;
    std::string single_indent;
    for(size_t i = 0; i < indent_len; i++) { single_indent += " "; }
    std::string indent_str;
    for(size_t i = 0; i < indent_level; i++) { indent_str += single_indent; }
    /* add indent */
    ostr << indent_str;
    /* if there are no hex bytes, just dump the name + "(NULL)" */
    if(len < 1) {
        ostr << name << ":  (NULL)";
        return ostr.str();
    }
    /* see if things will fit on one line */
    size_t name_len = name.length();
    /* calculate size of data with delim output as a hex string */
    size_t dump_len = (len * 2) + (delim.length() * (len - 1));
    /* if name + dump of data will fit on one line, print it as such */
    size_t one_line = (indent_level * indent_len) + (name_len + 3/*colon & 2 spaces*/) + dump_len;
    if(one_line < width) {
        ostr << name << ":  ";
        ostr << toHexString(data, len, delim) << std::endl;
        return ostr.str();
    }
    /* else format on multiple lines */
    ostr << name;
    ostr << ":" << std::endl;
    /* indent one extra level for the data portion */
    indent_level++;
    indent_str += single_indent;
    /* calculate bytes per row */
    size_t byte_width = 2 + delim.length();
    size_t bpr = (width - (indent_len * indent_level)) / byte_width;
    /* calculate rows & columns */
    size_t rows = len / bpr;
    size_t remain = len % bpr;
    for(size_t row = 0; row < rows; row++) {
        /* add indent */
        ostr << indent_str;
        /* add first val without delim */
        ostr << toHexString(data[row * bpr]);
        for(size_t col = 1; col < bpr; col++) {
            ostr << delim << toHexString(data[row * bpr + col]);
        }
        ostr << std::endl;
    }
    if(remain > 0) {
        /* add indent */
        ostr << indent_str;
        /* add first val without delim */
        ostr << toHexString(data[rows * bpr]);
        for(size_t col = 1; col < remain; col++) {
            ostr << delim << toHexString(data[rows * bpr + col]);
        }
        ostr << std::endl;
    }
    return ostr.str();
}

std::string NtbaUtil::toFormatHexString
    (const std::vector<unsigned char> &data, const std::string &name, size_t width, size_t indent_level)
{
    return toFormatHexString(&data[0], data.size(), name, width, indent_level);
}

/* use default delim & indent_len */
std::string NtbaUtil::toFormatHexString
    (const unsigned char *data, size_t len, const std::string &name, size_t width,
     size_t indent_level)
{
    return toFormatHexString(data, len, name, width, indent_level, ":", 4);
}

std::string NtbaUtil::toFormatHexString(const std::vector<unsigned char> &data, const std::string &name)
{
    return toFormatHexString(&data[0], data.size(), name);
}

std::string NtbaUtil::toFormatHexString(const unsigned char *data, size_t len, const std::string &name)
{
    return toFormatHexString(data, len, name, 80, 1);
}

// no data, just a name
std::string NtbaUtil::toFormatString
    (std::string name, size_t /* width */, size_t indent_level, size_t indent_len)
{
    // FIXME: If limiting the output to "width" columns is important, then that
    // computation needs to be added here.
    std::ostringstream ostr;
    std::string single_indent;
    for(size_t i = 0; i < indent_len; i++) { single_indent += " "; }
    std::string indent_str;
    for(size_t i = 0; i < indent_level; i++) { indent_str += single_indent; }
    ostr << indent_str << name << ":\n";
    return ostr.str();
}

std::string NtbaUtil::toHexString(const std::vector<unsigned char> &data, const std::string delim)
{
    return NtbaUtil::toHexString(&data[0], data.size(), delim);
}

std::string NtbaUtil::toHexString(const unsigned char *data, size_t len, const std::string delim)
{
    std::ostringstream ostr;
    if(len > 0) {
        // add first byte without delim
        ostr << toHexString(data[0]);
    }
    for(size_t i = 1; i < len; i++) {
        ostr << delim << toHexString(data[i]);
    }
    return ostr.str();
}

std::string NtbaUtil::toHexString(const std::vector<unsigned char> &data)
{
    return NtbaUtil::toHexString(&data[0], data.size());
}

std::string NtbaUtil::toHexString(const unsigned char *data, size_t len)
{
    return toHexString(data, len, /*delim*/std::string(" "));
}

std::string NtbaUtil::toHexString(unsigned char c)
{
    std::ostringstream ostr;
    if(c < 0x10) { ostr << "0"; }
    ostr << std::hex << (unsigned int)c;
    return ostr.str();
}

std::string NtbaUtil::toHexString(unsigned int i)
{
    std::ostringstream ostr;
    ostr << std::hex << i;
    return ostr.str();
}

std::string NtbaUtil::hexAsciiDump(const std::vector<unsigned char> &data, size_t bpl, const std::string delim)
{
    return hexAsciiDump(&data[0], data.size(), bpl, delim);
}

#if 0
std::string NtbaUtil::hexAsciiDump(const std::vector<unsigned char> &data, size_t bpl)
{
    return hexAsciiDump(data, bpl, Env::get_hex_delim());
}
#endif

std::string NtbaUtil::hexAsciiDump(const unsigned char *data, size_t len, size_t bpl)
{
    static const std::string delim(" ");
    return hexAsciiDump(data, len, bpl, delim);
}

std::string NtbaUtil::hexAsciiDump(const unsigned char *data, size_t len, size_t bpl,
                                     const std::string delim)
{
    std::ostringstream out;
    size_t remain = len % bpl;
    size_t rows = len / bpl;

    for(size_t row = 0; row < rows; row++) {
        std::ostringstream hex;
        std::ostringstream ascii;
        /* add first hex value without a delim */
        hex << toHexString(data[row * bpl]);
        ascii << toAlpha(data[row * bpl]);
        /* add all col >= 1 values with prepended delim */
        for(size_t col = 1; col < bpl; col++ ) {
            hex << delim << toHexString(data[row * bpl + col]);
            ascii << toAlpha(data[row * bpl + col]);
        }
        /* prepend each line with the byte number */
        out << toSpacedHexString(row * bpl, 6);
        out << ": ";
        out << hex.str();
        out << "    ";
        out << ascii.str();
        out << std::endl;
    }
    if(remain > 0) {
        std::ostringstream hex;
        std::ostringstream ascii;
        /* add first hex value without a delim */
        hex << toHexString(data[rows * bpl]);
        ascii << toAlpha(data[rows * bpl]);
        /* add all col >= 1 values with prepended delim */
        for(size_t col = 1; col < remain; col++ ) {
            hex << delim << toHexString(data[rows * bpl + col]);
            ascii << toAlpha(data[rows * bpl + col]);
        }
        for(size_t col = remain; col < bpl; col++) {
            hex << "   ";
            ascii << " ";
        }
        out << toSpacedHexString(rows * bpl, 6);
        out << ": ";
        out << hex.str();
        out << "    ";
        out << ascii.str();
        out << std::endl;
    }
    return out.str();
}

std::string NtbaUtil::toAlpha(unsigned char c)
{
    if(c >= 0x20 && c <= 0x7e) { return std::string(1, c); }
    return std::string(".");
}

std::string NtbaUtil::toSpacedHexString(size_t loc, size_t num_spaces)
{
    std::ostringstream out;
    std::string numstr = toHexString((unsigned int)loc);
    if(num_spaces > numstr.length()) {
        for(size_t j = 0, spaces = num_spaces - numstr.length(); j < spaces; j++) {
            out << " ";
        }
    }
    out << numstr;
    return out.str();
}

}} // namespae cadmium::crypto

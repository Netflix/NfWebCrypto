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
#include "JSONFormatter.h"
#include <sstream>
#include <limits>
#include <stdio.h>
#include "Variant.h"

using namespace std;

namespace   // anonymous
{

inline std::string escape(std::string string)
{
    //     \b  Backspace (ascii code 08)
    //     \f  Form feed (ascii code 0C)
    //     \n  New line
    //     \r  Carriage return
    //     \t  Tab
    //     \v  Vertical tab
    //     \'  Apostrophe or single quote
    //     \"  Double quote
    //     \\  Backslash caracter

    std::string result;
    bool hasEscape = false;

    int length = string.length();
    for(int i = 0; i < length; ++i) {
        switch (char ch = string[i]) {
            // case 8: // handled underneath
            // case 9:
            // case 10:
            // case 11:
            // case 12:
            // case 13:
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 14:
        case 15:
        case 16:
        case 17:
        case 18:
        case 19:
        case 20:
        case 21:
        case 22:
        case 23:
        case 24:
        case 25:
        case 26:
        case 27:
        case 28:
        case 29:
        case 30:
        case 31: { // escape non printable characters
            if(!hasEscape) {
                hasEscape = true;
                result = string.substr(0, i);
            }
            char buffer[7];
            snprintf(buffer, 7, "\\u%04x", ch);
            result.append(buffer);
            break; }
        case 8: // backspace
            if(!hasEscape) {
                hasEscape = true;
                result = string.substr(0, i);
            }
            result.append("\\b");
            break;
        case 12: // Form feed
            if(!hasEscape) {
                hasEscape = true;
                result = string.substr(0, i);
            }
            result.append("\\f");
            break;
        case '\n': // newline
            if(!hasEscape) {
                hasEscape = true;
                result = string.substr(0, i);
            }
            result.append("\\n");
            break;
        case '\t': // tab
            if(!hasEscape) {
                hasEscape = true;
                result = string.substr(0, i);
            }
            result.append("\\t");
            break;
        case '\v': // vertical tab
            if(!hasEscape) {
                hasEscape = true;
                result = string.substr(0, i);
            }
            result.append("\\v");
            break;
        case '\r': // carriage return
            if(!hasEscape) {
                hasEscape = true;
                result = string.substr(0, i);
            }
            result.append("\\r");
            break;
        case '"': // quote
            if(!hasEscape) {
                hasEscape = true;
                result = string.substr(0, i);
            }
            result.append("\\\"");
            break;
        case '\\': // backslash
            if(!hasEscape) {
                hasEscape = true;
                result = string.substr(0, i);
            }
            result.append("\\\\");
            break;
        default:
            if(hasEscape)
                result.push_back(ch);
            break;
        }
    }

    return hasEscape ? result : string;

}

}   // namespace anonymous

namespace cadmium { namespace base {

JSONFormatter::JSONFormatter(uint32_t flags)
    : mFlags(flags)
{
}

std::string JSONFormatter::format(const Variant &value, int indent) const
{
    std::ostringstream os;
    switch (value.type()) {
    case Variant::Null:
        if (!(mFlags & NullVariantToEmptyString))
            os << "null";
        break;
    case Variant::Custom:
        os << value.custom()->toString();
        break;
    case Variant::Integer:
        os << value.integer();
        break;
    case Variant::Double:
        os.precision(std::numeric_limits<double>::digits10);
        os << value.dbl();
        break;
    case Variant::Boolean:
        os << (value.boolean() ? "true" : "false");
        break;
    case Variant::String:
        os << '"' << ::escape(value.string()) << '"';
        break;
    case Variant::Array: {
        const std::vector<Variant> &array = value.array();
        if (!array.empty() || !(mFlags & NullVariantToEmptyString)) {
            const int length = array.size();
            if(mFlags & Pretty)
                os << " ";
            os << '[';
            if(mFlags & Pretty)
                os << "\n";
            if (length) {
                for (int i = 0; i < length; ++i) {
                    if (i > 0) {
                        os << ',';
                        if(mFlags & Pretty)
                            os << "\n";
                    }
                    if(mFlags & Pretty)
                        os << formatIndent(indent+1);
                    os << format(array[i], indent+1);
                }
            }
            if(mFlags & Pretty)
                os << "\n" << formatIndent(indent);
            os << ']';
        }
        break;
    }
    case Variant::Map: {
        if (!value.empty() || !(mFlags & NullVariantToEmptyString)) {
            //" o":{"foo":"hello","bar":[1,3,"foo"]}
            if(mFlags & Pretty)
                os << " ";
            os << '{';
            const std::map<std::string, Variant>::const_iterator end = value.end();
            const std::map<std::string, Variant>::const_iterator begin = value.begin();
            if(mFlags & Pretty)
                os << "\n";
            for (std::map<std::string, Variant>::const_iterator it = begin; it != end; ++it) {
                const std::pair<std::string, Variant> &node = *it;
                if (it != begin) {
                    os << ',';
                    if(mFlags & Pretty)
                        os << "\n";
                }
                if(mFlags & Pretty)
                    os << formatIndent(indent+1);
                os << '"' << escape(node.first) << "\":";
                if(mFlags & Pretty)
                    os << " ";
                os << format(node.second, indent+1);
            }
            if(mFlags & Pretty)
                os << "\n" << formatIndent(indent);
            os << '}';
        }
        break;
    }
    }
    return os.str();
}

const char *JSONFormatter::mimeType() const
{
    return "application/json";
}

std::string JSONFormatter::formatIndent(int indent)
{
    std::string result;
    for(int i = 0; i < indent; ++i)
        result += "   ";
    return result;
}

}}  // namespace cadmium::base

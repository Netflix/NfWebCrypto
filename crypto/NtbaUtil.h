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
#ifndef __NTBAUTIL_H__
#define __NTBAUTIL_H__

#include <string>
#include <vector>

namespace cadmium {
namespace crypto {

/**
 * Utility functions.
 */
class NtbaUtil
{
public:
	/**
	 * Print as a binary string.
	 */
	static std::string toBinaryString(unsigned char c);

	/**
	 * Determine whether an integer is a power of two.
	 */
	static bool isPowerOf2(unsigned int i);

	/**
	 * Format (pretty-print) byte data.
	 * @param data input data
	 * @param name the name of the data field
	 * @param width the column width of the output
	 * @param indent_level the number of indents at which to place this data
	 * @param delim the delimeter between bytes
	 * @param indent_len the number of spaces per indent
	 * @return a formatted string containing a hex dump of the data
	 */
	static std::string toFormatHexString
		(const std::vector<unsigned char> &data, const std::string &name, size_t width,
		 size_t indent_level, const std::string &delim, size_t indent_len);

	/**
	 * Format (pretty-print) byte data.
	 * @param data input data
	 * @param len length of input data
	 * @param name the name of the data field
	 * @param width the column width of the output
	 * @param indent_level the number of indents at which to place this data
	 * @param delim the delimeter between bytes
	 * @param indent_len the number of spaces per indent
	 * @return a formatted string containing a hex dump of the data
	 */
	static std::string toFormatHexString
		(const unsigned char *data, size_t len, const std::string &name, size_t width,
		 size_t indent_level, const std::string &delim, size_t indent_len);

	/**
	 * Format (pretty-print) byte data.
	 * This version of the method uses the default delimeter and indent_len as returned
	 * by ntba::Env::get_hex_delim() and ntba::Env::get_indent_spaces().
	 * @param data input data
	 * @param len length of input data
	 * @param name the name of the data field
	 * @param width the column width of the output
	 * @param indent_level the number of indents at which to place this data
	 * @return a formatted string containing a hex dump of the data
	 * @see ntba::Env::get_hex_delim()
	 * @see ntba::Env::get_indent_spaces().
	 */
	static std::string toFormatHexString
		(const std::vector<unsigned char> &data, const std::string &name, size_t width, size_t indent_level);

	/**
	 * Format (pretty-print) byte data.
	 * This version of the method uses the default delimeter and indent_len as returned
	 * by ntba::Env::get_hex_delim() and ntba::Env::get_indent_spaces().
	 * @param data input data
	 * @param len length of input data
	 * @param name the name of the data field
	 * @param width the column width of the output
	 * @param indent_level the number of indents at which to place this data
	 * @return a formatted string containing a hex dump of the data
	 * @see ntba::Env::get_hex_delim()
	 * @see ntba::Env::get_indent_spaces().
	 */
	static std::string toFormatHexString
		(const unsigned char *data, size_t len, const std::string &name, size_t width,
		 size_t indent_level);

    /**
     * Format (pretty-print) byte data.
     * This version of the method used the default column width,
     * indent_level, delimiter, and indent_len as returned by
     * ntba::Env::get_screen_width(), ntba::Env::get_indent_level(),
     * ntba::Env::get_hex_delim(), and ntba::Env::get_index_spaces().
     *
     * @param data input data.
     * @param name the name of the data field.
     * @return a formatting string containing a hex dump of the data.
     * @see ntba::Env::get_screen_width()
     * @see ntba::Env::get_indent_level()
     * @see ntba::Env::get_hex_delim()
     * @see ntba::Env::get_indent_spaces()
     */
    static std::string toFormatHexString
        (const std::vector<unsigned char> &data, const std::string &name);

    /**
     * Format (pretty-print) byte data.
     * This version of the method used the default column width,
     * indent_level, delimiter, and indent_len as returned by
     * ntba::Env::get_screen_width(), ntba::Env::get_indent_level(),
     * ntba::Env::get_hex_delim(), and ntba::Env::get_index_spaces().
     *
     * @param data input data.
     * @param len length of input data.
     * @param name the name of the data field.
     * @return a formatting string containing a hex dump of the data.
     * @see ntba::Env::get_screen_width()
     * @see ntba::Env::get_indent_level()
     * @see ntba::Env::get_hex_delim()
     * @see ntba::Env::get_indent_spaces()
     */
    static std::string toFormatHexString
        (const unsigned char *data, size_t len, const std::string &name);

	/**
	 * Format (pretty-print) a single name string.
	 * @param name the name of the data field
	 * @param width the column width of the output
	 * @param indent_level the number of indents at which to place this data
	 * @param indent_len the number of spaces per indent
	 * @return a formatted string containing a properly indented name
	 */
	static std::string toFormatString
		(std::string name, size_t width, size_t indent_level, size_t indent_len);

	/**
	 * Print byte data.
	 * @param data input data
	 * @param len length of input data
	 * @param delim the delimeter between bytes
	 * @return a hex dump of the data
	 */
	static std::string toHexString(const unsigned char *data, size_t len,
								   const std::string delim);
	/**
	 * Print byte data.
	 * @param data input data.
	 * @param delim the delimeter between bytes
	 * @return a hex dump of the data
	 */
	static std::string toHexString(const std::vector<unsigned char> &data, const std::string delim);
	/**
	 * Print byte data.
	 * This version of the method uses the default delimeter as returned by
	 * ntba::Env::get_hex_delim().
	 * @param data input data
	 * @param len length of input data
	 * @param delim the delimeter between bytes
	 * @return a hex dump of the data
	 * @see ntba::Env::get_hex_delim()
	 */
	static std::string toHexString(const unsigned char *data, size_t len);
	/**
	 * Print byte data.
	 * This version of the method uses the default delimeter as returned by
	 * ntba::Env::get_hex_delim().
	 * @param data input data.
	 * @param delim the delimeter between bytes
	 * @return a hex dump of the data
	 * @see ntba::Env::get_hex_delim()
	 */
	static std::string toHexString(const std::vector<unsigned char> &data);
	/**
	 * Dump hex data & corresponding ASCII character output.
	 * This method prints data in two blocks; the left hand block contains the
	 * hex output, and the right hand block contains ASCII characters.  When
	 * the ASCII character is not printable a '.' is used.
	 * @param data input data
	 * @param bpl bytes per line
	 * @param delim the delimeter between bytes
	 * @return a string with hex & ASCII output
	 */
	static std::string hexAsciiDump(const std::vector<unsigned char> &data, size_t bpl,
									const std::string delim);
	/**
	 * Dump hex data & corresponding ASCII character output.
	 * This method prints data in two blocks; the left hand block contains the
	 * hex output, and the right hand block contains ASCII characters.  When
	 * the ASCII character is not printable a '.' is used.
	 * This version of the method uses the default delimeter as returned by
	 * ntba::Env::get_hex_delim().
	 * @param data input data
	 * @param bpl bytes per line
	 * @param delim the delimeter between bytes
	 * @return a string with hex & ASCII output
	 * @see ntba::Env::get_hex_delim()
	 */
	static std::string hexAsciiDump(const std::vector<unsigned char> &data, size_t bpl);
	/**
	 * Dump hex data & corresponding ASCII character output.
	 * This method prints data in two blocks; the left hand block contains the
	 * hex output, and the right hand block contains ASCII characters.  When
	 * the ASCII character is not printable a '.' is used.
	 * @param data input data
	 * @param len the length of the input data
	 * @param bpl bytes per line
	 * @param delim the delimeter between bytes
	 * @return a string with hex & ASCII output
	 */
	static std::string hexAsciiDump(const unsigned char *data, size_t len, size_t bpl,
									const std::string delim);
	/**
	 * Dump hex data & corresponding ASCII character output.
	 * This method prints data in two blocks; the left hand block contains the
	 * hex output, and the right hand block contains ASCII characters.  When
	 * the ASCII character is not printable a '.' is used.
	 * This version of the method uses the default delimeter as returned by
	 * ntba::Env::get_hex_delim().
	 * @param data input data
	 * @param len the length of the input data
	 * @param bpl bytes per line
	 * @return a string with hex & ASCII output
	 * @see ntba::Env::get_hex_delim()
	 */
	static std::string hexAsciiDump(const unsigned char *data, size_t len, size_t bpl);
	static std::string toHexString(unsigned char c);
	static std::string toHexString(unsigned int i);
private:
	static std::string toAlpha(unsigned char c);
	static std::string toSpacedHexString(size_t loc, size_t num_spaces);
};

}} // namespace cadmium::crypto

#endif // __NTBAUTIL_H__

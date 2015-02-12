/*
 * Copyright(c) 2015 Tim Ruehsen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * This file is part of libvtls.
 */

#include <sys/types.h>

static const char _lower[256] = {
	['a'] = 'a', ['b'] = 'b', ['c'] = 'c', ['d'] = 'd',
	['e'] = 'e', ['f'] = 'f', ['g'] = 'g', ['h'] = 'h',
	['i'] = 'i', ['j'] = 'j', ['k'] = 'k', ['l'] = 'l',
	['m'] = 'm', ['n'] = 'n', ['o'] = 'o', ['p'] = 'p',
	['q'] = 'q', ['r'] = 'r', ['s'] = 's', ['t'] = 't',
	['u'] = 'u', ['v'] = 'v', ['w'] = 'w', ['x'] = 'x',
	['y'] = 'y', ['z'] = 'z', ['A'] = 'a', ['B'] = 'b',
	['C'] = 'c', ['D'] = 'd', ['E'] = 'e', ['F'] = 'f',
	['G'] = 'g', ['H'] = 'h', ['I'] = 'i', ['J'] = 'j',
	['K'] = 'k', ['L'] = 'l', ['M'] = 'm', ['N'] = 'n',
	['O'] = 'o', ['P'] = 'p', ['Q'] = 'q', ['R'] = 'r',
	['S'] = 's', ['T'] = 't', ['U'] = 'u', ['V'] = 'v',
	['W'] = 'w', ['X'] = 'x', ['Y'] = 'y', ['Z'] = 'z',
};

/**
 * vtls_strcasecmp_ascii:
 * @s1: String
 * @s2: String
 *
 * This functions compares @s1 and @s2 case insensitive ignoring locale settings.
 * It also accepts %NULL values.
 *
 * It returns 0 if both @s1 and @s2 are the same disregarding case for ASCII letters a-z.
 * It returns 0 if both @s1 and @s2 are %NULL.
 * It returns <0 if @s1 is %NULL and @s2 is not %NULL or s1 is smaller than s2.
 * It returns >0 if @s2 is %NULL and @s1 is not %NULL or s1 is greater than s2.
 *
 * Returns: An integer value described above.
 */
int vtls_strcasecmp_ascii(const char *s1, const char *s2)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else {
			while (*s1 && (*s1 == *s2 || (_lower[(unsigned)*s1] && _lower[(unsigned)*s1] == _lower[(unsigned)*s2]))) {
				s1++;
				s2++;
			}

			if (*s1 || *s2)
				return *s1 - *s2;

			return 0;
		}
	}
}

/**
 * vtls_strncasecmp_ascii:
 * @s1: String
 * @s2: String
 * @n: Max. number of chars to compare
 *
 * This functions compares @s1 and @s2 case insensitive ignoring locale settings up to a max number of @n chars.
 * It also accepts %NULL values.
 *
 * It returns 0 if both @s1 and @s2 are the same disregarding case for ASCII letters a-z.
 * It returns 0 if both @s1 and @s2 are %NULL.
 * It returns <0 if @s1 is %NULL and @s2 is not %NULL or s1 is smaller than s2.
 * It returns >0 if @s2 is %NULL and @s1 is not %NULL or s1 is greater than s2.
 *
 * Returns: An integer value described above.
 */
int vtls_strncasecmp_ascii(const char *s1, const char *s2, size_t n)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else {
			while ((ssize_t)(n--) > 0 && *s1 && (*s1 == *s2 || (_lower[(unsigned)*s1] && _lower[(unsigned)*s1] == _lower[(unsigned)*s2]))) {
				s1++;
				s2++;
			}

			if ((ssize_t)n >= 0 && (*s1 || *s2))
				return *s1 - *s2;

			return 0;
		}
	}
}

int vtls_strcaseequal_ascii(const char* s1, const char* s2)
{
	return vtls_strcasecmp_ascii(s1, s2) == 0;
}

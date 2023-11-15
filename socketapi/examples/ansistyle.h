/*
 * ansistyle.h: ANSI escape sequence settings
 * $Id: ansistyle.h 2069 2016-11-28 16:41:11Z dreibh $
 *
 * Copyright (C) 2003-2024 by Thomas Dreibholz
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Contact: thomas.dreibholz@gmail.com
 */


#ifndef ANSISTYLE_H
#define ANSISTYLE_H

#include <iostream>


#define COLOR_BLACK     0
#define COLOR_RED       1
#define COLOR_GREEN     2
#define COLOR_YELLOW    3
#define COLOR_BLUE      4
#define COLOR_MAGENTA   5
#define COLOR_CYAN      6
#define COLOR_WHITE     7
#define COLOR_DEFAULT   9

#define ATTR_INTENSIVE  (1 << 1)
#define ATTR_UNDERLINE  (1 << 2)
#define ATTR_BLINK      (1 << 3)
#define ATTR_REVERSE    (1 << 4)


inline void ansiStyle(std::ostream&      os,
                      const unsigned int fg,
                      const unsigned int bg,
                      const unsigned int attribute)
{
   os << "\x1b[" << 30 + (fg & 0x0f) << ";" << 40 + (bg & 0x0f) << ";"
      << 1 + ((attribute & ATTR_INTENSIVE) ? 0 : 20) << ";"
      << 4 + ((attribute & ATTR_UNDERLINE) ? 0 : 20) << ";"
      << 5 + ((attribute & ATTR_BLINK) ? 0 : 20) << ";"
      << 7 + ((attribute & ATTR_REVERSE) ? 0 : 20) << "m";
}


inline void ansiReset(std::ostream& os)
{
   os << "\x1b[0m";
}


#endif

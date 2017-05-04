/*
 * safeprint.cc: Safely print a block of text
 *
 * Copyright (C) 2003-2017 by Thomas Dreibholz
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
 * Contact: dreibh@iem.uni-due.de
 */

#include <iostream>
#include <unistd.h>

#include "ansistyle.h"


void safePrint(std::ostream& os,
               const char*   buffer,
               const size_t  size)
{
   for(size_t i = 0;i < size;i++) {
      if((isprint(buffer[i])) || ((unsigned char)buffer[i] >= 160)) {
         ansiStyle(os, COLOR_BLUE, COLOR_DEFAULT, ATTR_INTENSIVE);
         os << buffer[i];
      }
      else if(buffer[i] == '\r') {
         // Omit "carriage return" character.
      }
      else if(buffer[i] == '\n') {
         os << std::endl;
      }
      else {
         ansiStyle(os, COLOR_RED, COLOR_DEFAULT, ATTR_INTENSIVE);
         os << "?";
      }
   }
   ansiReset(os);
}

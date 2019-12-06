/*
 * ansireset.cc: Reset ANSI terminal
 *
 * Copyright (C) 2003-2020 by Thomas Dreibholz
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ansistyle.h"


using namespace std;


int main()
{
   ansiReset(cout);
/*
   unsigned char x = 128 + 27;
   cout << x << "2J"
        << x << "1;1H"
        << "\x9b" "?25h" << endl; // set_mode on - cursor on/off
*/
   return(0);
}

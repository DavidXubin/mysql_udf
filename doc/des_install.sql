/*
 *                       Written by JoungKyun.Kim
 *            Copyright (c) 2013 JoungKyun.Kim <http://oops.org>
 *
 * -----------------------------------------------------------------------------
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2.1 of the License, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * -----------------------------------------------------------------------------
 * This file is part of lib_mysqludf_aes267
 *
 * $Id$
 */


DROP FUNCTION IF EXISTS my_des_decrypt;

CREATE FUNCTION my_des_decrypt RETURNS string SONAME 'mysq1_des_udf.so';

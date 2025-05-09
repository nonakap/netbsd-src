/*	$NetBSD: ds28e17iicreg.h,v 1.1 2025/01/23 19:02:42 brad Exp $	*/

/*
 * Copyright (c) 2025 Brad Spencer <brad@anduin.eldar.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _DEV_I2C_DS28E17IICREG_H_
#define _DEV_I2C_DS28E17IICREG_H_

#define DS28E17IIC_DC_WD_WITH_STOP	0x4B
#define DS28E17IIC_DC_WD		0x5A
#define DS28E17IIC_DC_WD_ONLY		0x69
#define DS28E17IIC_DC_WD_ONLY_WITH_STOP	0x78
#define DS28E17IIC_DC_RD_WITH_STOP	0x87
#define DS28E17IIC_DC_WD_RD_WITH_STOP	0x2D
#define DS28E17IIC_DC_WRITE_CONFIG	0xD2
#define DS28E17IIC_DC_READ_CONFIG	0xE1
#define		DS28E17IIC_SPEED_100KHZ		0x00
#define		DS28E17IIC_SPEED_400KHZ		0x01
#define		DS28E17IIC_SPEED_900KHZ		0x02
#define DS28E17IIC_DC_ENTER_SLEEP	0x1E
#define DS28E17IIC_DC_DEV_REVISION	0xC3

#endif

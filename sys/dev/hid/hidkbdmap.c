/*	$NetBSD: hidkbdmap.c,v 1.16 2025/05/24 16:50:54 nia Exp $	*/

/*
 * Copyright (c) 1999,2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Lennart Augustsson (lennart@augustsson.net) at
 * Carlstedt Research & Technology.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: hidkbdmap.c,v 1.16 2025/05/24 16:50:54 nia Exp $");

#include <sys/param.h>
#include <sys/types.h>
#include <dev/wscons/wsksymdef.h>
#include <dev/wscons/wsksymvar.h>

#include <dev/usb/usb.h>

#define KC(n)		KS_KEYCODE(n)

Static const keysym_t hidkbd_keydesc_us[] = {
/*  pos      command		normal		shifted */
    KC(4), 			KS_a,
    KC(5), 			KS_b,
    KC(6), 			KS_c,
    KC(7), 			KS_d,
    KC(8), 			KS_e,
    KC(9), 			KS_f,
    KC(10), 			KS_g,
    KC(11), 			KS_h,
    KC(12), 			KS_i,
    KC(13), 			KS_j,
    KC(14), 			KS_k,
    KC(15), 			KS_l,
    KC(16), 			KS_m,
    KC(17), 			KS_n,
    KC(18), 			KS_o,
    KC(19), 			KS_p,
    KC(20), 			KS_q,
    KC(21), 			KS_r,
    KC(22), 			KS_s,
    KC(23), 			KS_t,
    KC(24), 			KS_u,
    KC(25), 			KS_v,
    KC(26), 			KS_w,
    KC(27), 			KS_x,
    KC(28), 			KS_y,
    KC(29), 			KS_z,
    KC(30),  			KS_1,		KS_exclam,
    KC(31),  			KS_2,		KS_at,
    KC(32),  			KS_3,		KS_numbersign,
    KC(33),  			KS_4,		KS_dollar,
    KC(34),  			KS_5,		KS_percent,
    KC(35),  			KS_6,		KS_asciicircum,
    KC(36),  			KS_7,		KS_ampersand,
    KC(37),  			KS_8,		KS_asterisk,
    KC(38), 			KS_9,		KS_parenleft,
    KC(39), 			KS_0,		KS_parenright,
    KC(40), 			KS_Return,
    KC(41),   KS_Cmd_Debugger,	KS_Escape,
    KC(42), 			KS_BackSpace,
    KC(43), 			KS_Tab,
    KC(44), 			KS_space,
    KC(45), 			KS_minus,	KS_underscore,
    KC(46), 			KS_equal,	KS_plus,
    KC(47), 			KS_bracketleft,	KS_braceleft,
    KC(48), 			KS_bracketright,KS_braceright,
    KC(49), 			KS_backslash,	KS_bar,
    KC(50), 			KS_backslash,	KS_bar,
    KC(51), 			KS_semicolon,	KS_colon,
    KC(52), 			KS_apostrophe,	KS_quotedbl,
    KC(53), 			KS_grave,	KS_asciitilde,
    KC(54), 			KS_comma,	KS_less,
    KC(55), 			KS_period,	KS_greater,
    KC(56), 			KS_slash,	KS_question,
    KC(57), 			KS_Caps_Lock,
    KC(58),  KS_Cmd_Screen0,	KS_f1,
    KC(59),  KS_Cmd_Screen1,	KS_f2,
    KC(60),  KS_Cmd_Screen2,	KS_f3,
    KC(61),  KS_Cmd_Screen3,	KS_f4,
    KC(62),  KS_Cmd_Screen4,	KS_f5,
    KC(63),  KS_Cmd_Screen5,	KS_f6,
    KC(64),  KS_Cmd_Screen6,	KS_f7,
    KC(65),  KS_Cmd_Screen7,	KS_f8,
    KC(66),  KS_Cmd_Screen8,	KS_f9,
    KC(67),  KS_Cmd_Screen9,	KS_f10,
    KC(68), 			KS_f11,
    KC(69), 			KS_f12,
    KC(70),			KS_Print_Screen,
    KC(71), 			KS_Hold_Screen,
    KC(72),			KS_Pause,
    KC(73),			KS_Insert,
    KC(74),			KS_Home,
    KC(75), KS_Cmd_ScrollFastUp, KS_Prior,
    KC(76),			KS_Delete,
    KC(77),			KS_End,
    KC(78), KS_Cmd_ScrollFastDown, KS_Next,
    KC(79),			KS_Right,
    KC(80),			KS_Left,
    KC(81),			KS_Down,
    KC(82),			KS_Up,
    KC(83), 			KS_Num_Lock,
    KC(84),			KS_KP_Divide,
    KC(85), 			KS_KP_Multiply,
    KC(86), 			KS_KP_Subtract,
    KC(87), 			KS_KP_Add,
    KC(88),			KS_KP_Enter,
    KC(89), 			KS_KP_End,	KS_KP_1,
    KC(90), 			KS_KP_Down,	KS_KP_2,
    KC(91), KS_Cmd_ScrollFastDown, KS_KP_Next,	KS_KP_3,
    KC(92), 			KS_KP_Left,	KS_KP_4,
    KC(93), 			KS_KP_Begin,	KS_KP_5,
    KC(94), 			KS_KP_Right,	KS_KP_6,
    KC(95), 			KS_KP_Home,	KS_KP_7,
    KC(96), 			KS_KP_Up,	KS_KP_8,
    KC(97), KS_Cmd_ScrollFastUp, KS_KP_Prior,	KS_KP_9,
    KC(98), 			KS_KP_Insert,	KS_KP_0,
    KC(99), 			KS_KP_Delete,	KS_KP_Decimal,
    KC(100),			KS_backslash,	KS_bar,
    KC(101),			KS_Menu,
/* ... */
    KC(104), 			KS_f13,
    KC(105), 			KS_f14,
    KC(106), 			KS_f15,
    KC(107), 			KS_f16,
/* ... */
    KC(109),			KS_Power,
/* ... many unmapped keys ... */
    KC(224),  KS_Cmd1,		KS_Control_L,
    KC(225), 			KS_Shift_L,
    KC(226),  KS_Cmd2,		KS_Alt_L,
    KC(227),			KS_Meta_L,
    KC(228),			KS_Control_R,
    KC(229), 			KS_Shift_R,
    KC(230),			KS_Alt_R,	KS_Multi_key,
    KC(231),			KS_Meta_R,
};

Static const keysym_t hidkbd_keydesc_jp[] = {
/*  pos      command		normal			shifted */
    KC(31),  			KS_2,			KS_quotedbl,
    KC(35),  			KS_6,			KS_ampersand,
    KC(36),  			KS_7,			KS_apostrophe,
    KC(37),  			KS_8,			KS_parenleft,
    KC(38), 			KS_9,			KS_parenright,
    KC(39), 			KS_0,
    KC(45),			KS_minus,		KS_equal,
    KC(46),			KS_asciicircum,		KS_asciitilde,
    KC(47),			KS_at,			KS_grave,
    KC(48),			KS_bracketleft,		KS_braceleft,
    KC(49), /* ARCHISS */	KS_bracketright,	KS_braceright,
    KC(50), /* other model */	KS_bracketright,	KS_braceright,
    KC(51),			KS_semicolon,		KS_plus,
    KC(52),			KS_colon,		KS_asterisk,
    KC(53), 			KS_Zenkaku_Hankaku, /* replace grave/tilde */
    KC(135),			KS_backslash,		KS_underscore,
    KC(136),			KS_Hiragana_Katakana,
    KC(137),			KS_backslash,		KS_bar,
    KC(138),			KS_Henkan,
    KC(139),			KS_Muhenkan,
};

Static const keysym_t hidkbd_keydesc_us_dvorak[] = {
/*  pos      command		normal			shifted */
    KC(4), 			KS_a,
    KC(5), 			KS_x,
    KC(6), 			KS_j,
    KC(7), 			KS_e,
    KC(8), 			KS_period,		KS_greater,
    KC(9), 			KS_u,
    KC(10), 			KS_i,
    KC(11), 			KS_d,
    KC(12), 			KS_c,
    KC(13), 			KS_h,
    KC(14), 			KS_t,
    KC(15), 			KS_n,
    KC(16), 			KS_m,
    KC(17), 			KS_b,
    KC(18), 			KS_r,
    KC(19), 			KS_l,
    KC(20), 			KS_apostrophe,		KS_quotedbl,
    KC(21), 			KS_p,
    KC(22), 			KS_o,
    KC(23), 			KS_y,
    KC(24), 			KS_g,
    KC(25), 			KS_k,
    KC(26), 			KS_comma,		KS_less,
    KC(27), 			KS_q,
    KC(28), 			KS_f,
    KC(29), 			KS_semicolon,		KS_colon,
    KC(45), 			KS_bracketleft,		KS_braceleft,
    KC(46), 			KS_bracketright,	KS_braceright,
    KC(47), 			KS_slash,		KS_question,
    KC(48), 			KS_equal,		KS_plus,
    KC(51), 			KS_s,
    KC(52), 			KS_minus,		KS_underscore,
    KC(54), 			KS_w,
    KC(55), 			KS_v,
    KC(56), 			KS_z,
};

Static const keysym_t hidkbd_keydesc_us_colemak[] = {
/*  pos      command		normal		shifted */
    KC(4), 			KS_a,		KS_A,		KS_aacute,	KS_Aacute,
    KC(5), 			KS_b,		KS_B,		KS_asciitilde,	KS_asciitilde,
    KC(6), 			KS_c,		KS_C,		KS_ccedilla,	KS_Ccedilla,
    KC(7), 			KS_s,		KS_S,		KS_ssharp,	KS_asciitilde,
    KC(8), 			KS_f,		KS_F,		KS_atilde,	KS_Atilde,
    KC(9), 			KS_t,		KS_T,		KS_dead_acute,	KS_asciitilde,
    KC(10), 			KS_d,		KS_D,		KS_dead_diaeresis, KS_asciitilde,
    KC(11), 			KS_h,		KS_H,		KS_asciitilde,	KS_asciitilde,
    KC(12), 			KS_u,		KS_U,		KS_uacute,	KS_Uacute,
    KC(13), 			KS_n,		KS_N,		KS_ntilde,	KS_Ntilde,
    KC(14), 			KS_e,		KS_E,		KS_eacute,	KS_Eacute,
    KC(15), 			KS_i,		KS_I,		KS_iacute,	KS_Iacute,
    KC(16), 			KS_m,		KS_M,		KS_asciitilde,	KS_asciitilde,
    KC(17), 			KS_k,		KS_K,		KS_asciitilde,	KS_asciitilde,
    KC(18), 			KS_y,		KS_Y,		KS_udiaeresis,	KS_Udiaeresis,
    KC(19), 			KS_semicolon,	KS_colon,	KS_odiaeresis,	KS_Odiaeresis,
    KC(20), 			KS_q,		KS_Q,		KS_adiaeresis,	KS_Adiaeresis,
    KC(21), 			KS_p,		KS_P,		KS_oslash,	KS_Ooblique,
    KC(22), 			KS_r,		KS_R,		KS_dead_grave,	KS_asciitilde,
    KC(23), 			KS_g,		KS_G,		KS_asciitilde,	KS_asciitilde,
    KC(24), 			KS_l,		KS_L,		KS_asciitilde,	KS_asciitilde,
    KC(25), 			KS_v,		KS_V,		KS_asciitilde,	KS_asciitilde,
    KC(26), 			KS_w,		KS_W,		KS_aring,	KS_Aring,
    KC(27), 			KS_x,		KS_X,		KS_dead_circumflex, KS_asciitilde,
    KC(28), 			KS_j,		KS_J,		KS_asciitilde,	KS_asciitilde,
    KC(29), 			KS_z,		KS_Z,		KS_ae,		KS_AE,
    KC(30),  			KS_1,		KS_exclam,	KS_exclamdown,	KS_onesuperior,
    KC(31),  			KS_2,		KS_at,		KS_masculine,	KS_twosuperior,
    KC(32),  			KS_3,		KS_numbersign,	KS_ordfeminine,	KS_threesuperior,
    KC(33),  			KS_4,		KS_dollar,	KS_cent,	KS_sterling,
    KC(34),  			KS_5,		KS_percent,	KS_asciitilde,	KS_yen,
    KC(35),  			KS_6,		KS_asciicircum,	KS_asciitilde,	KS_asciitilde,
    KC(36),  			KS_7,		KS_ampersand,	KS_eth,		KS_ETH,
    KC(37),  			KS_8,		KS_asterisk,	KS_thorn,	KS_THORN,
    KC(38), 			KS_9,		KS_parenleft,	KS_asciitilde,	KS_asciitilde,
    KC(39), 			KS_0,		KS_parenright,	KS_asciitilde,	KS_asciitilde,
    KC(44), 			KS_space,	KS_space,	KS_space,	KS_nobreakspace,
    KC(45), 			KS_minus,	KS_underscore,	KS_asciitilde,	KS_asciitilde,
    KC(46), 			KS_equal,	KS_plus,	KS_multiply,	KS_division,
    KC(47), 			KS_bracketleft,	KS_braceleft,	KS_guillemotleft, KS_asciitilde,
    KC(48), 			KS_bracketright, KS_braceright,	KS_guillemotright, KS_asciitilde,
    KC(49), 			KS_backslash,	KS_bar,		KS_asciitilde,	KS_asciitilde,
    KC(50), 			KS_backslash,	KS_bar,		KS_asciitilde,	KS_asciitilde,
    KC(51), 			KS_o,		KS_O,		KS_oacute,	KS_Oacute,
    KC(52), 			KS_apostrophe,	KS_quotedbl,	KS_otilde,	KS_Otilde,
    KC(53), 			KS_grave,	KS_asciitilde,	KS_dead_tilde,	KS_asciitilde,
    KC(54), 			KS_comma,	KS_less,	KS_dead_cedilla, KS_asciitilde,
    KC(55), 			KS_period,	KS_greater,	KS_asciitilde,	KS_asciitilde,
    KC(56), 			KS_slash,	KS_question,	KS_questiondown, KS_asciitilde,
    KC(57), 			KS_BackSpace,
    KC(100), 			KS_minus,	KS_underscore,	KS_asciitilde,	KS_asciitilde,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

Static const keysym_t hidkbd_keydesc_swapctrlcaps[] = {
/*  pos      command		normal		shifted */
    KC(57),  KS_Cmd1,		KS_Control_L,
    KC(224), 			KS_Caps_Lock,
};

/* switch screens using Command-F* as on ADB keyboards */
Static const keysym_t hidkbd_keydesc_apple[] = {
/*  pos      command		normal		shifted */
    KC(224),			KS_Control_L,
    KC(226),			KS_Alt_L,
    KC(227),  KS_Cmd,		KS_Meta_L,
};

Static const keysym_t hidkbd_keydesc_de[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(16),  KS_m,		KS_M,		KS_mu,
    KC(20),  KS_q,		KS_Q,		KS_at,
    KC(28),  KS_z,
    KC(29),  KS_y,
    KC(31),  KS_2,		KS_quotedbl,	KS_twosuperior,
    KC(32),  KS_3,		KS_section,	KS_threesuperior,
    KC(35),  KS_6,		KS_ampersand,
    KC(36),  KS_7,		KS_slash,	KS_braceleft,
    KC(37),  KS_8,		KS_parenleft,	KS_bracketleft,
    KC(38),  KS_9,		KS_parenright,	KS_bracketright,
    KC(39),  KS_0,		KS_equal,	KS_braceright,
    KC(45),  KS_ssharp,		KS_question,	KS_backslash,
    KC(46),  KS_dead_acute,	KS_dead_grave,
    KC(47),  KS_udiaeresis,
    KC(48),  KS_plus,		KS_asterisk,	KS_dead_tilde,
    KC(50),  KS_numbersign,	KS_apostrophe,
    KC(51),  KS_odiaeresis,
    KC(52),  KS_adiaeresis,
    KC(53),  KS_dead_circumflex,KS_dead_abovering,
    KC(54),  KS_comma,		KS_semicolon,
    KC(55),  KS_period,		KS_colon,
    KC(56),  KS_minus,		KS_underscore,
    KC(100), KS_less,		KS_greater,	KS_bar,		KS_brokenbar,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

Static const keysym_t hidkbd_keydesc_de_nodead[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(46),  KS_apostrophe,	KS_grave,
    KC(48),  KS_plus,		KS_asterisk,	KS_asciitilde,
    KC(53),  KS_asciicircum,	KS_degree,
};

Static const keysym_t hidkbd_keydesc_de_neo[] = {
/*  pos     normal		shifted 	layer 3		layer 4 */
    KC(53),  KS_dead_circumflex,	KS_dead_caron,
    KC(30),  KS_1,		KS_degree,	KS_onesuperior,	KS_ordfeminine,
    KC(31),  KS_2,		KS_section,	KS_twosuperior,	KS_masculine,
    KC(32),  KS_3,		KS_l,		KS_threesuperior,KS_numbersign,
    KC(33),  KS_4,		KS_guillemotright,KS_greater,
    KC(34),  KS_5,		KS_guillemotleft,KS_less,	KS_periodcentered,
    KC(35),  KS_6,		KS_dollar,	KS_cent,	KS_sterling,
    KC(36),  KS_7,		KS_currency,	KS_yen,		KS_currency,
    KC(37),  KS_8,		KS_quotedbl,	KS_quotedbl,	KS_Tab,
    KC(38),  KS_9,		KS_quotedbl,	KS_quotedbl,	KS_KP_Divide,
    KC(39),  KS_0,		KS_quotedbl,	KS_quotedbl,	KS_KP_Multiply,
    KC(45),  KS_minus,		KS_hyphen,	KS_minus,	KS_minus,
    KC(46),  KS_dead_grave,	KS_dead_cedilla,KS_dead_abovering,
    KC(20),  KS_x,		KS_X,		KS_period,	KS_Prior,
    KC(26),  KS_v,		KS_V,		KS_underscore,	KS_BackSpace,
    KC(8),   KS_l,		KS_L,		KS_bracketleft,	KS_Up,
    KC(21),  KS_c,		KS_C,		KS_bracketright,KS_Delete,
    KC(23),  KS_w,		KS_W,		KS_asciicircum,	KS_Next,
    KC(28),  KS_k,		KS_K,		KS_exclam,	KS_exclamdown,
    KC(24),  KS_h,		KS_H,		KS_less,	KS_KP_7,
    KC(12),  KS_g,		KS_G,		KS_greater,	KS_KP_8,
    KC(18),  KS_f,		KS_F,		KS_equal,	KS_KP_9,
    KC(19),  KS_q,		KS_Q,		KS_ampersand,	KS_KP_Add,
    KC(47),  KS_ssharp,		KS_ssharp,	KS_f,		KS_KP_Subtract,
    KC(48),  KS_dead_acute,	KS_dead_tilde,
    KC(4),   KS_u,		KS_U,		KS_backslash,	KS_Home,
    KC(22),  KS_i,		KS_I,		KS_slash,	KS_Left,
    KC(7),   KS_a,		KS_A,		KS_braceleft,	KS_Down,
    KC(9),   KS_e,		KS_E,		KS_braceright,	KS_Right,
    KC(10),  KS_o,		KS_O,		KS_asterisk,	KS_End,
    KC(11),  KS_s,		KS_S,		KS_question,	KS_questiondown,
    KC(13),  KS_n,		KS_N,		KS_parenleft,	KS_KP_4,
    KC(14),  KS_r,		KS_R,		KS_parenright,	KS_KP_5,
    KC(15),  KS_t,		KS_T,		KS_minus,	KS_KP_6,
    KC(51),  KS_d,		KS_D,		KS_colon,	KS_KP_Separator,
    KC(52),  KS_y,		KS_Y,		KS_at,		KS_KP_Decimal,
    KC(29),  KS_udiaeresis,	KS_Udiaeresis,	KS_numbersign,	KS_Escape,
    KC(27),  KS_odiaeresis,	KS_Odiaeresis,	KS_dollar,	KS_Tab,
    KC(6),   KS_adiaeresis,	KS_Adiaeresis,	KS_bar,		KS_Insert,
    KC(25),  KS_p,		KS_P,		KS_asciitilde,	KS_Return,
    KC(5),   KS_z,		KS_Z,		KS_grave,	KS_Undo,
    KC(17),  KS_b,		KS_B,		KS_plus,	KS_colon,
    KC(16),  KS_m,		KS_M,		KS_percent,	KS_KP_1,
    KC(54),  KS_comma,		KS_minus,	KS_quotedbl,	KS_KP_2,
    KC(55),  KS_period,		KS_period,	KS_apostrophe,	KS_KP_3,
    KC(56),  KS_j,		KS_J,		KS_semicolon,	KS_semicolon,
    KC(50),  KS_Mode_switch,	KS_Multi_key,
    KC(57),  KS_Mode_switch,	KS_Multi_key,
    KC(100), KS_Mode_switch,	KS_Multi_key,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

Static const keysym_t hidkbd_keydesc_dk[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(31),  KS_2,		KS_quotedbl,	KS_at,
    KC(32),  KS_3,		KS_numbersign,	KS_sterling,
    KC(33),  KS_4,		KS_currency,	KS_dollar,
    KC(35),  KS_6,		KS_ampersand,
    KC(36),  KS_7,		KS_slash,	KS_braceleft,
    KC(37),  KS_8,		KS_parenleft,	KS_bracketleft,
    KC(38),  KS_9,		KS_parenright,	KS_bracketright,
    KC(39),  KS_0,		KS_equal,	KS_braceright,
    KC(45),  KS_plus,		KS_question,
    KC(46),  KS_dead_acute,	KS_dead_grave,	KS_bar,
    KC(47),  KS_aring,
    KC(48),  KS_dead_diaeresis,	KS_dead_circumflex, KS_dead_tilde,
    KC(50),  KS_apostrophe,	KS_asterisk,
    KC(51),  KS_ae,
    KC(52),  KS_oslash,
    KC(53),  KS_onehalf,	KS_paragraph,
    KC(54),  KS_comma,		KS_semicolon,
    KC(55),  KS_period,		KS_colon,
    KC(56),  KS_minus,		KS_underscore,
    KC(100), KS_less,		KS_greater,	KS_backslash,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

Static const keysym_t hidkbd_keydesc_dk_nodead[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(46),  KS_apostrophe,	KS_grave,	KS_bar,
    KC(48),  KS_diaeresis,	KS_asciicircum,	KS_asciitilde,
};

Static const keysym_t hidkbd_keydesc_sv[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(45),  KS_plus,		KS_question,	KS_backslash,
    KC(48),  KS_dead_diaeresis,	KS_dead_circumflex, KS_dead_tilde,
    KC(50),  KS_apostrophe,	KS_asterisk,
    KC(51),  KS_odiaeresis,
    KC(52),  KS_adiaeresis,
    KC(53),  KS_paragraph,	KS_onehalf,
    KC(100), KS_less,		KS_greater,	KS_bar,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

Static const keysym_t hidkbd_keydesc_sv_nodead[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(46),  KS_apostrophe,	KS_grave,	KS_bar,
    KC(48),  KS_diaeresis,	KS_asciicircum,	KS_asciitilde,
};

Static const keysym_t hidkbd_keydesc_ee[] = {
/*  pos      normal             shifted         altgr                   shift-altgr */
    KC(22),  KS_s,		KS_S,		KS_scaron,		KS_Scaron,
    KC(29),  KS_z,		KS_Z,		KS_zcaron,		KS_Zcaron,
    KC(47),  KS_udiaeresis,	KS_Udiaeresis,	KS_dead_diaeresis,	KS_dead_abovering,
    KC(48),  KS_otilde,		KS_Otilde,	KS_section,
    KC(50),  KS_apostrophe,	KS_asterisk,	KS_onehalf,		KS_dead_breve,
    KC(52),  KS_adiaeresis,	KS_Adiaeresis,	KS_asciicircum,		KS_dead_caron,
    KC(53),  KS_dead_caron,	KS_dead_tilde,	KS_notsign,		KS_notsign,
};

Static const keysym_t hidkbd_keydesc_ee_nodead[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(53),  KS_asciicircum,	KS_asciitilde,	KS_notsign,	KS_notsign,
};

Static const keysym_t hidkbd_keydesc_no[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(46),  KS_backslash,	KS_dead_grave,	KS_dead_acute,
    KC(48),  KS_dead_diaeresis,	KS_dead_circumflex, KS_dead_tilde,
    KC(50),  KS_comma,		KS_asterisk,
    KC(51),  KS_oslash,
    KC(52),  KS_ae,
    KC(53),  KS_bar,		KS_paragraph,
    KC(100), KS_less,		KS_greater,
};

Static const keysym_t hidkbd_keydesc_no_nodead[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(46),  KS_backslash,	KS_grave,	KS_acute,
    KC(48),  KS_diaeresis,	KS_asciicircum,	KS_asciitilde,
};

Static const keysym_t hidkbd_keydesc_fr[] = {
/*  pos	     normal		shifted		altgr		shift-altgr */
    KC(4),   KS_q,
    KC(16),  KS_comma,		KS_question,
    KC(20),  KS_a,
    KC(26),  KS_z,
    KC(29),  KS_w,
    KC(30),  KS_ampersand,	KS_1,
    KC(31),  KS_eacute,		KS_2,		KS_asciitilde,
    KC(32),  KS_quotedbl,	KS_3,		KS_numbersign,
    KC(33),  KS_apostrophe,	KS_4,		KS_braceleft,
    KC(34),  KS_parenleft,	KS_5,		KS_bracketleft,
    KC(35),  KS_minus,		KS_6,		KS_bar,
    KC(36),  KS_egrave,		KS_7,		KS_grave,
    KC(37),  KS_underscore,	KS_8,		KS_backslash,
    KC(38),  KS_ccedilla,	KS_9,		KS_asciicircum,
    KC(39),  KS_agrave,		KS_0,		KS_at,
    KC(45),  KS_parenright,	KS_degree,	KS_bracketright,
    KC(46),  KS_equal,		KS_plus,	KS_braceright,
    KC(47),  KS_dead_circumflex, KS_dead_diaeresis,
    KC(48),  KS_dollar,		KS_sterling,	KS_currency,
    KC(50),  KS_asterisk,	KS_mu,
    KC(51),  KS_m,
    KC(52),  KS_ugrave,		KS_percent,
    KC(53),  KS_twosuperior,
    KC(54),  KS_semicolon,	KS_period,
    KC(55),  KS_colon,		KS_slash,
    KC(56),  KS_exclam,		KS_section,
    KC(100), KS_less,		KS_greater,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

Static const keysym_t hidkbd_keydesc_fr_bepo[] = {
/*  pos	    normal		shifted		altgr		shift-altgr */
    KC(53),  KS_dollar,		KS_numbersign,
    KC(30),  KS_quotedbl,	KS_1,
    KC(31),  KS_guillemotleft,	KS_2,		KS_less,
    KC(32),  KS_guillemotright,	KS_3,		KS_greater,
    KC(33),  KS_parenleft,	KS_4,		KS_bracketleft,
    KC(34),  KS_parenright,	KS_5,		KS_bracketright,
    KC(35),  KS_at,		KS_6,		KS_asciicircum,
    KC(36),  KS_plus,		KS_7,		KS_plusminus,
    KC(37),  KS_minus,		KS_8,
    KC(38),  KS_slash,		KS_9,		KS_division,
    KC(39),  KS_asterisk,	KS_0,		KS_multiply,
    KC(45),  KS_equal,		KS_degree,
    KC(46),  KS_percent,	KS_grave,
    KC(20),  KS_b,		KS_B,		KS_bar,		KS_underscore,
    KC(26),  KS_eacute,		KS_Eacute,	KS_dead_acute,
    KC(8),   KS_p,		KS_P,		KS_ampersand,	KS_section,
    KC(21),  KS_o,		KS_O,
    KC(23),  KS_egrave,		KS_Egrave,	KS_dead_grave,	KS_grave,
    KC(28),  KS_dead_circumflex,KS_exclam,	KS_exclamdown,
    KC(24),  KS_v,		KS_V,		KS_dead_caron,
    KC(12),  KS_d,		KS_D,
    KC(18),  KS_l,		KS_L,		KS_sterling,
    KC(19),  KS_j,		KS_J,
    KC(47),  KS_z,		KS_Z,
    KC(48),  KS_w,		KS_W,
    KC(4),   KS_a,		KS_A,		KS_ae,		KS_AE,
    KC(22),  KS_u,		KS_U,		KS_ugrave,	KS_Ugrave,
    KC(7),   KS_i,		KS_I,		KS_dead_diaeresis,
    KC(9),   KS_e,		KS_E,		KS_currency,
    KC(10),  KS_comma,		KS_semicolon,	KS_apostrophe,
    KC(11),  KS_c,		KS_C,		KS_dead_cedilla,KS_copyright,
    KC(13),  KS_t,		KS_T,
    KC(14),  KS_s,		KS_S,
    KC(15),  KS_r,		KS_R,		KS_dead_breve,	KS_registered,
    KC(51),  KS_n,		KS_N,		KS_dead_tilde,
    KC(52),  KS_m,		KS_M,
    KC(50),  KS_ccedilla,	KS_Ccedilla,
    KC(29),  KS_agrave,		KS_Agrave,	KS_backslash,
    KC(27),  KS_y,		KS_Y,		KS_braceleft,
    KC(6),   KS_x,		KS_X,		KS_braceright,
    KC(25),  KS_period,		KS_colon,
    KC(5),   KS_k,		KS_K,		KS_asciitilde,
    KC(17),  KS_apostrophe,	KS_question,	KS_questiondown,
    KC(16),  KS_q,		KS_Q,		KS_dead_abovering,
    KC(54),  KS_g,		KS_G,
    KC(55),  KS_h,		KS_H,
    KC(56),  KS_f,		KS_F,		KS_dead_ogonek,
    KC(44),  KS_space,		KS_space,	KS_underscore,	KS_nobreakspace,
    KC(100), KS_ecircumflex,	KS_Ecircumflex,	KS_slash,	KS_asciicircum,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

Static const keysym_t hidkbd_keydesc_be[] = {
/*  pos	     normal		shifted		altgr		shift-altgr */
    KC(30),  KS_ampersand,	KS_1,		KS_bar,
    KC(31),  KS_eacute,		KS_2,		KS_at,
    KC(33),  KS_apostrophe,	KS_4,
    KC(34),  KS_parenleft,	KS_5,
    KC(35),  KS_section,	KS_6,		KS_asciicircum,
    KC(36),  KS_egrave,		KS_7,
    KC(37),  KS_exclam,		KS_8,
    KC(38),  KS_ccedilla,	KS_9,		KS_braceleft,
    KC(39),  KS_agrave,		KS_0,		KS_braceright,
    KC(45),  KS_parenright,	KS_degree,
    KC(46),  KS_minus,		KS_underscore,
    KC(47),  KS_dead_circumflex, KS_dead_diaeresis,	KS_bracketleft,
    KC(48),  KS_dollar,		KS_asterisk,	KS_bracketright,
    KC(50),  KS_mu,		KS_sterling,	KS_grave,
    KC(52),  KS_ugrave,		KS_percent,	KS_acute,
    KC(53),  KS_twosuperior,	KS_threesuperior,
    KC(56),  KS_equal,		KS_plus,	KS_asciitilde,
    KC(100), KS_less,		KS_greater,	KS_backslash,
};

Static const keysym_t hidkbd_keydesc_it[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(31),  KS_2,	    	KS_quotedbl,	KS_twosuperior,
    KC(32),  KS_3,	    	KS_sterling,	KS_threesuperior,
    KC(33),  KS_4,	    	KS_dollar,
    KC(34),  KS_5,	    	KS_percent,
    KC(35),  KS_6,	    	KS_ampersand,
    KC(36),  KS_7,	    	KS_slash,
    KC(37),  KS_8,	    	KS_parenleft,
    KC(38),  KS_9,	    	KS_parenright,
    KC(39),  KS_0,	    	KS_equal,
    KC(45),  KS_apostrophe,	KS_question,
    KC(46),  KS_igrave,	    	KS_asciicircum,
    KC(47),  KS_egrave,		KS_eacute,	KS_braceleft,	KS_bracketleft,
    KC(48),  KS_plus,		KS_asterisk,	KS_braceright,	KS_bracketright,
    KC(49),  KS_ugrave,		KS_section,
    KC(51),  KS_ograve,		KS_Ccedilla,	KS_at,
    KC(52),  KS_agrave,		KS_degree,	KS_numbersign,
    KC(53),  KS_backslash,	KS_bar,
    KC(54),  KS_comma,		KS_semicolon,
    KC(55),  KS_period,		KS_colon,
    KC(56),  KS_minus,		KS_underscore,
    KC(100), KS_less,		KS_greater,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

Static const keysym_t hidkbd_keydesc_uk[] = {
/*  pos      normal             shifted         altgr           shift-altgr */
    KC(30),  KS_1,              KS_exclam,      KS_plusminus,   KS_exclamdown,
    KC(31),  KS_2,              KS_quotedbl,    KS_twosuperior, KS_cent,
    KC(32),  KS_3,              KS_sterling,    KS_threesuperior,
    KC(33),  KS_4,              KS_dollar,      KS_acute,       KS_currency,
    KC(34),  KS_5,              KS_percent,     KS_mu,          KS_yen,
    KC(35),  KS_6,              KS_asciicircum, KS_paragraph,
    KC(36),  KS_7,              KS_ampersand,   KS_periodcentered, KS_brokenbar,
    KC(37),  KS_8,              KS_asterisk,    KS_cedilla,     KS_ordfeminine,
    KC(38),  KS_9,              KS_parenleft,   KS_onesuperior, KS_diaeresis,
    KC(39),  KS_0,              KS_parenright,  KS_masculine,   KS_copyright,
    KC(45),  KS_minus,          KS_underscore,  KS_hyphen,      KS_ssharp,
    KC(46),  KS_equal,          KS_plus,        KS_onehalf,    KS_guillemotleft,
    KC(49),  KS_numbersign,     KS_asciitilde,  KS_sterling,    KS_thorn,
    KC(50),  KS_numbersign,	KS_asciitilde,
    KC(52),  KS_apostrophe,     KS_at,          KS_section,     KS_Agrave,
    KC(53),  KS_grave,          KS_grave,       KS_agrave,      KS_agrave,
    KC(100), KS_backslash,      KS_bar,         KS_Udiaeresis,
};

Static const keysym_t hidkbd_keydesc_es[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(30),  KS_1,		KS_exclam,	KS_bar,
    KC(31),  KS_2,		KS_quotedbl,	KS_at,
    KC(32),  KS_3,		KS_periodcentered, KS_numbersign,
    KC(33),  KS_4,		KS_dollar,	KS_asciitilde,
    KC(35),  KS_6,		KS_ampersand,
    KC(36),  KS_7,		KS_slash,
    KC(37),  KS_8,		KS_parenleft,
    KC(38),  KS_9,		KS_parenright,
    KC(39),  KS_0,		KS_equal,
    KC(45),  KS_apostrophe,	KS_question,
    KC(46),  KS_exclamdown,	KS_questiondown,
    KC(47),  KS_dead_grave,	KS_dead_circumflex, KS_bracketleft,
    KC(48),  KS_plus,		KS_asterisk,	KS_bracketright,
    KC(49),  KS_ccedilla,	KS_Ccedilla,	KS_braceright,
    KC(50),  KS_ccedilla,	KS_Ccedilla,	KS_braceright,
    KC(51),  KS_ntilde,
    KC(52),  KS_dead_acute,	KS_dead_diaeresis, KS_braceleft,
    KC(53),  KS_degree,		KS_ordfeminine,	KS_backslash,
    KC(54),  KS_comma,		KS_semicolon,
    KC(55),  KS_period,		KS_colon,
    KC(56),  KS_minus,		KS_underscore,
    KC(100), KS_less,		KS_greater,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

Static const keysym_t hidkbd_keydesc_pt[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(31),  KS_2,		KS_quotedbl,	KS_at,
    KC(32),  KS_3,		KS_numbersign,	KS_sterling,
    KC(35),  KS_6,		KS_ampersand,
    KC(36),  KS_7,		KS_slash,	KS_braceleft,
    KC(37),  KS_8,		KS_parenleft,	KS_bracketleft,
    KC(38),  KS_9,		KS_parenright,	KS_bracketright,
    KC(39),  KS_0,		KS_equal,	KS_braceright,
    KC(45),  KS_apostrophe,	KS_question,
    KC(46),  KS_plus,		KS_asterisk,
    KC(47),  KS_plus,		KS_asterisk,
    KC(48),  KS_dead_acute,	KS_dead_grave,
    KC(49),  KS_less,		KS_greater,
    KC(50),  KS_dead_tilde,	KS_dead_circumflex,
    KC(51),  KS_ccedilla,	KS_Ccedilla,
    KC(52),  KS_masculine,	KS_ordfeminine,
    KC(53),  KS_backslash,	KS_bar,
    KC(54),  KS_comma,		KS_semicolon,
    KC(55),  KS_period,		KS_colon,
    KC(56),  KS_minus,		KS_underscore,
    KC(100), KS_less,		KS_greater,
    KC(226), KS_Mode_switch,	KS_Multi_key,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

Static const keysym_t hidkbd_keydesc_sg[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(30),  KS_1,		KS_plus,	KS_bar,
    KC(31),  KS_2,		KS_quotedbl,	KS_at,
    KC(32),  KS_3,		KS_asterisk,	KS_numbersign,
    KC(33),  KS_4,		KS_ccedilla,
    KC(35),  KS_6,		KS_ampersand,	KS_notsign,
    KC(36),  KS_7,		KS_slash,	KS_brokenbar,
    KC(37),  KS_8,		KS_parenleft,	KS_cent,
    KC(38),  KS_9,		KS_parenright,
    KC(39),  KS_0,		KS_equal,
    KC(45),  KS_apostrophe,	KS_question,	KS_dead_acute,
    KC(46),  KS_dead_circumflex,KS_dead_grave,	KS_dead_tilde,
    KC(8),   KS_e,		KS_E,		KS_currency,
    KC(28),  KS_z,
    KC(47),  KS_udiaeresis,	KS_egrave,	KS_bracketleft,
    KC(48),  KS_dead_diaeresis,	KS_exclam,	KS_bracketright,
    KC(51),  KS_odiaeresis,	KS_eacute,
    KC(52),  KS_adiaeresis,	KS_agrave,	KS_braceleft,
    KC(53),  KS_section,	KS_degree,	KS_dead_abovering,
    KC(50),  KS_dollar,		KS_sterling,	KS_braceright,
    KC(29),  KS_y,
    KC(54),  KS_comma,		KS_semicolon,
    KC(55),  KS_period,		KS_colon,
    KC(56),  KS_minus,		KS_underscore,
    KC(100), KS_less,		KS_greater,	KS_backslash,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

Static const keysym_t hidkbd_keydesc_sg_nodead[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(45),  KS_apostrophe,	KS_question,	KS_acute,
    KC(46),  KS_asciicircum,	KS_grave,	KS_asciitilde,
    KC(48),  KS_diaeresis,	KS_exclam,	KS_bracketright
};

Static const keysym_t hidkbd_keydesc_sf[] = {
/*  pos      normal            shifted         altgr           shift-altgr */
    KC(47),  KS_egrave,        KS_udiaeresis,  KS_bracketleft,
    KC(51),  KS_eacute,        KS_odiaeresis,
    KC(52),  KS_agrave,        KS_adiaeresis,  KS_braceleft
};

static const keysym_t hidkbd_keydesc_hu[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(5),   KS_b,		KS_B,		KS_braceleft,
    KC(6),   KS_c,		KS_C,		KS_ampersand,
    KC(9),   KS_f,		KS_F,		KS_bracketleft,
    KC(10),  KS_g,		KS_G,		KS_bracketright,
    KC(17),  KS_n,		KS_N,		KS_braceright,
    KC(20),  KS_q,		KS_Q,		KS_backslash,
    KC(25),  KS_v,		KS_V,		KS_at,
    KC(26),  KS_w,		KS_W,		KS_bar,
    KC(27),  KS_x,		KS_X,		KS_numbersign,
    KC(28),  KS_z,
    KC(29),  KS_y,		KS_Y,		KS_greater,
    KC(30),  KS_1,		KS_apostrophe,	KS_asciitilde,
    KC(31),  KS_2,		KS_quotedbl,	KS_dead_caron,
    KC(32),  KS_3,		KS_plus,	KS_asciicircum,
    KC(33),  KS_4,		KS_exclam,	KS_dead_breve,
    KC(34),  KS_5,		KS_percent,	KS_dead_abovering,
    KC(35),  KS_6,		KS_slash,	KS_dead_ogonek,
    KC(36),  KS_7,		KS_equal,	KS_grave,
    KC(37),  KS_8,		KS_parenleft,	KS_dead_dotaccent,
    KC(38),  KS_9,		KS_parenright,	KS_dead_acute,
    KC(39),  KS_odiaeresis,	KS_Odiaeresis,	KS_dead_hungarumlaut,
    KC(45),  KS_udiaeresis,	KS_Udiaeresis,	KS_dead_diaeresis,
    KC(46),  KS_oacute,		KS_Oacute,	KS_dead_cedilla,
    KC(47),  KS_odoubleacute,	KS_Odoubleacute,KS_division,
    KC(48),  KS_uacute,		KS_Uacute,	KS_multiply,
    KC(49),  KS_udoubleacute,	KS_Udoubleacute,KS_currency,
    KC(50),  KS_iacute,		KS_Iacute,	KS_less,
    KC(51),  KS_eacute,		KS_Eacute,	KS_dollar,
    KC(52),  KS_aacute,		KS_Aacute,	KS_ssharp,
    KC(53),  KS_0,		KS_section,
    KC(54),  KS_comma,		KS_question,	KS_semicolon,
    KC(55),  KS_period,		KS_colon,
    KC(56),  KS_minus,		KS_underscore,	KS_asterisk,
    KC(230), KS_Mode_switch,	KS_Multi_key
};

static const keysym_t hidkbd_keydesc_br[] = {
/*  pos      normal             shifted                 altgr                   shift-altgr */
    KC(6),   KS_c,		KS_C,			KS_copyright,		KS_copyright,
    KC(8),   KS_e,		KS_E,			KS_currency,		KS_currency,
    KC(16),  KS_m,		KS_M,			KS_mu,			KS_mu,
    KC(20),  KS_q,		KS_Q,			KS_slash,		KS_slash,
    KC(21),  KS_r,		KS_R,			KS_registered,		KS_registered,
    KC(26),  KS_w,		KS_W,			KS_question,		KS_question,
    KC(30),  KS_1,		KS_exclam,		KS_onesuperior,		KS_exclamdown,
    KC(31),  KS_2,		KS_at,			KS_twosuperior,		KS_onehalf,
    KC(32),  KS_3,		KS_numbersign,		KS_threesuperior,	KS_threequarters,
    KC(33),  KS_4,		KS_dollar,		KS_sterling,		KS_onequarter,
    KC(34),  KS_5,		KS_percent,		KS_cent,		KS_cent,
    KC(35),  KS_6,		KS_dead_diaeresis,	KS_notsign,		KS_diaeresis,
    KC(46),  KS_equal,		KS_plus,		KS_section,		KS_dead_ogonek,
    KC(47),  KS_dead_acute,	KS_dead_grave,		KS_acute,		KS_grave,
    KC(48),  KS_bracketleft,	KS_braceleft,		KS_ordfeminine,		KS_macron,
    KC(49),  KS_bracketright,	KS_braceright,		KS_masculine,		KS_masculine,
    KC(50),  KS_bracketright,	KS_braceright,		KS_masculine,		KS_masculine,
    KC(51),  KS_ccedilla,	KS_Ccedilla,		KS_dead_acute,		KS_dead_hungarumlaut,
    KC(52),  KS_dead_tilde,	KS_dead_circumflex,	KS_asciitilde,		KS_asciicircum,
    KC(53),  KS_apostrophe,	KS_quotedbl,		KS_notsign,		KS_notsign,
    KC(56),  KS_semicolon,	KS_colon,		KS_dead_dotaccent,	KS_abovedot,
    KC(100), KS_backslash,	KS_bar,			KS_masculine,		KS_dead_breve,
    KC(135), KS_slash,		KS_question,		KS_degree,		KS_questiondown,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

static const keysym_t hidkbd_keydesc_br_nodead[] = {
/*  pos      normal             shifted         altgr           shift-altgr */
    KC(35),  KS_6,		KS_diaeresis,	KS_notsign,	KS_dead_diaeresis,
    KC(47),  KS_apostrophe,	KS_grave,	KS_dead_acute,	KS_dead_grave,
    KC(52),  KS_asciitilde,	KS_asciicircum,	KS_dead_tilde,	KS_dead_circumflex,
};

static const keysym_t hidkbd_keydesc_tr[] = {
/*  pos      normal		shifted         altgr           shift-altgr */
    KC(12),  KS_L5_idotless,	KS_I,
    KC(20),  KS_q,		KS_Q,		KS_at,
    KC(31),  KS_2,		KS_apostrophe,	KS_sterling,
    KC(32),  KS_3,		KS_asciicircum,	KS_numbersign,
    KC(33),  KS_4,		KS_plus,	KS_dollar,
    KC(34),  KS_5,		KS_percent,	KS_onehalf,
    KC(35),  KS_6,		KS_ampersand,
    KC(36),  KS_7,		KS_slash,	KS_braceleft,
    KC(37),  KS_8,		KS_parenleft,	KS_bracketleft,
    KC(38),  KS_9,		KS_parenright,	KS_bracketright,
    KC(39),  KS_0,		KS_equal,	KS_braceright,
    KC(45),  KS_asterisk,	KS_question,	KS_backslash,
    KC(46),  KS_minus,	KS_underscore,
    KC(47),  KS_L5_gbreve,	KS_L5_Gbreve,	KS_dead_diaeresis,
    KC(48),  KS_udiaeresis,	KS_Udiaeresis,	KS_asciitilde,
    KC(49),  KS_comma,	KS_semicolon,	KS_dead_grave,
    KC(50),  KS_comma,	KS_semicolon,	KS_dead_grave,
    KC(51),  KS_L5_scedilla,	KS_L5_Scedilla,	KS_dead_acute,
    KC(52),  KS_i,		KS_L5_Idotabove,
    KC(53),  KS_quotedbl,	KS_eacute,
    KC(54),  KS_odiaeresis,	KS_Odiaeresis,
    KC(55),  KS_ccedilla,	KS_Ccedilla,
    KC(56),  KS_period,	KS_colon,
    KC(100), KS_less,	KS_greater,	KS_bar,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

static const keysym_t hidkbd_keydesc_tr_nodead[] = {
/*  pos      normal		shifted         altgr           shift-altgr */
    KC(47),  KS_L5_gbreve,	KS_L5_Gbreve,
    KC(49),  KS_comma,		KS_semicolon,	KS_grave,
    KC(50),  KS_comma,		KS_semicolon,	KS_grave,
    KC(51),  KS_L5_scedilla,	KS_L5_Scedilla,	KS_apostrophe,
};

static const keysym_t hidkbd_keydesc_is[] = {
/*  pos      normal		shifted			altgr			shift-altgr */
    KC(8),   KS_e,		KS_E,			KS_currency,		KS_cent,
    KC(16),  KS_m,		KS_M,			KS_mu,
    KC(20),  KS_q,		KS_Q,			KS_at,
    KC(30),  KS_1,		KS_exclam,		KS_onesuperior,		KS_exclamdown,
    KC(31),  KS_2,		KS_quotedbl,		KS_twosuperior,		KS_currency,
    KC(32),  KS_3,		KS_numbersign,		KS_threesuperior,	KS_sterling,
    KC(33),  KS_4,		KS_dollar,		KS_onequarter,
    KC(34),  KS_5,		KS_percent,		KS_onehalf,
    KC(35),  KS_6,		KS_ampersand,		KS_notsign,
    KC(36),  KS_7,		KS_slash,		KS_braceleft,
    KC(37),  KS_8,		KS_parenleft,		KS_bracketleft,
    KC(38),  KS_9,		KS_parenright,		KS_bracketright,	KS_plusminus,
    KC(39),  KS_0,		KS_equal,		KS_braceright,		KS_degree,
    KC(45),  KS_odiaeresis,	KS_Odiaeresis,		KS_backslash,		KS_questiondown,
    KC(46),  KS_minus,		KS_underscore,		KS_dead_cedilla,	KS_dead_ogonek,
    KC(47),  KS_eth,		KS_ETH,			KS_dead_diaeresis,	KS_dead_abovering,
    KC(48),  KS_apostrophe,	KS_question,		KS_asciitilde,
    KC(49),  KS_plus,		KS_asterisk,		KS_grave,		KS_dead_breve,
    KC(50),  KS_plus,		KS_asterisk,		KS_grave,		KS_dead_breve,
    KC(51),  KS_ae,		KS_AE,			KS_asciicircum,		KS_dead_hungarumlaut,
    KC(52),  KS_dead_acute,	KS_dead_diaeresis,	KS_dead_circumflex,
    KC(53),  KS_degree,		KS_diaeresis,
    KC(54),  KS_comma,		KS_semicolon,
    KC(55),  KS_period,		KS_colon,		KS_periodcentered,	KS_division,
    KC(56),  KS_thorn,		KS_THORN,
    KC(100), KS_less,		KS_greater,		KS_bar,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

static const keysym_t hidkbd_keydesc_is_nodead[] = {
/*  pos      normal	shifted		altgr		shift-altgr */
    KC(52),  KS_acute,	KS_diaeresis,	KS_asciicircum,
};

static const keysym_t hidkbd_keydesc_la[] = {
/*  pos      normal		shifted			altgr			shift-altgr */
    KC(20),  KS_q,		KS_Q,			KS_at,
    KC(30),  KS_1,		KS_exclam,		KS_bar,
    KC(31),  KS_2,		KS_quotedbl,		KS_at,
    KC(32),  KS_3,		KS_numbersign,		KS_periodcentered,
    KC(35),  KS_6,		KS_ampersand,		KS_notsign,
    KC(36),  KS_7,		KS_slash,
    KC(37),  KS_8,		KS_parenleft,
    KC(38),  KS_9,		KS_parenright,
    KC(39),  KS_0,		KS_equal,
    KC(45),  KS_apostrophe,	KS_question,		KS_backslash,
    KC(46),  KS_questiondown,	KS_exclamdown,		KS_dead_cedilla,	KS_dead_ogonek,
    KC(47),  KS_dead_acute,	KS_dead_diaeresis,	KS_dead_diaeresis,	KS_dead_abovering,
    KC(48),  KS_plus,		KS_asterisk,		KS_asciitilde,
    KC(49),  KS_braceright,	KS_bracketright,	KS_dead_grave,
    KC(50),  KS_braceright,	KS_bracketright,	KS_dead_grave,
    KC(51),  KS_ntilde,		KS_Ntilde,		KS_asciitilde,
    KC(52),  KS_braceleft,	KS_bracketleft,		KS_dead_circumflex,
    KC(53),  KS_bar,		KS_degree,		KS_notsign,
    KC(54),  KS_comma,		KS_semicolon,
    KC(55),  KS_period,		KS_colon,
    KC(56),  KS_minus,		KS_underscore,
    KC(100), KS_less,		KS_greater,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

static const keysym_t hidkbd_keydesc_cf[] = {
/*  pos      normal		shifted			altgr		shift-altgr */
    KC(16),  KS_m,		KS_M,			KS_mu,
    KC(18),  KS_o,		KS_O,			KS_section,
    KC(19),  KS_p,		KS_P,			KS_paragraph,
    KC(30),  KS_1,		KS_exclam,		KS_plusminus,
    KC(31),  KS_2,		KS_quotedbl,		KS_at,
    KC(32),  KS_3,		KS_slash,		KS_sterling,
    KC(33),  KS_4,		KS_dollar,		KS_cent,
    KC(34),  KS_5,		KS_percent,		KS_currency,
    KC(35),  KS_6,		KS_question,		KS_notsign,
    KC(36),  KS_7,		KS_ampersand,		KS_brokenbar,
    KC(37),  KS_8,		KS_asterisk,		KS_twosuperior,
    KC(38),  KS_9,		KS_parenleft,		KS_threesuperior,
    KC(39),  KS_0,		KS_parenright,		KS_onequarter,
    KC(44),  KS_space,		KS_space,		KS_nobreakspace,
    KC(45),  KS_minus,		KS_underscore,		KS_onehalf,
    KC(46),  KS_equal,		KS_plus,		KS_threequarters,
    KC(47),  KS_dead_circumflex,KS_dead_circumflex,	KS_bracketleft,
    KC(48),  KS_dead_cedilla,	KS_dead_diaeresis,	KS_bracketright,
    KC(49),  KS_less,		KS_greater,		KS_braceright,
    KC(50),  KS_less,		KS_greater,		KS_braceright,
    KC(51),  KS_semicolon,	KS_colon,		KS_asciitilde,
    KC(52),  KS_dead_grave,	KS_dead_grave,		KS_braceleft,
    KC(53),  KS_numbersign,	KS_bar,			KS_backslash,
    KC(54),  KS_comma,		KS_apostrophe,		KS_macron,
    KC(55),  KS_period,		KS_period,		KS_hyphen,
    KC(56),  KS_eacute,		KS_Eacute,		KS_dead_acute,
    KC(100), KS_guillemotleft,	KS_guillemotright,	KS_degree,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

static const keysym_t hidkbd_keydesc_pl[] = {
/*  pos      normal		shifted		altgr		shift-altgr */
    KC(4),   KS_a,		KS_A,		KS_aogonek,	KS_Aogonek,
    KC(6),   KS_c,		KS_C,		KS_aacute,	KS_Aacute,
    KC(8),   KS_e,		KS_E,		KS_eogonek,	KS_Eogonek,
    KC(15),  KS_l,		KS_L,		KS_lstroke,	KS_Lstroke,
    KC(17),  KS_n,		KS_N,		KS_nacute,	KS_Nacute,
    KC(18),  KS_o,		KS_O,		KS_oacute,	KS_Oacute,
    KC(22),  KS_s,		KS_S,		KS_sacute,	KS_Sacute,
    KC(24),  KS_u,		KS_U,		KS_currency,	KS_currency,
    KC(27),  KS_x,		KS_X,		KS_zacute,	KS_Zacute,
    KC(29),  KS_z,		KS_Z,		KS_zabovedot,	KS_Zabovedot,
    KC(34),  KS_5,		KS_percent,	KS_currency,
    KC(230), KS_Mode_switch,	KS_Multi_key,
};

#define KBD_MAP(name, base, map) \
			{ name, base, sizeof(map)/sizeof(keysym_t), map }

const struct wscons_keydesc hidkbd_keydesctab[] = {
	KBD_MAP(KB_US,			0,	hidkbd_keydesc_us),
	KBD_MAP(KB_US | KB_SWAPCTRLCAPS,KB_US,	hidkbd_keydesc_swapctrlcaps),
	KBD_MAP(KB_US | KB_DVORAK,	KB_US,	hidkbd_keydesc_us_dvorak),
	KBD_MAP(KB_US | KB_DVORAK | KB_SWAPCTRLCAPS,	KB_US| KB_DVORAK,
		hidkbd_keydesc_swapctrlcaps),
	KBD_MAP(KB_US | KB_COLEMAK,	KB_US,	hidkbd_keydesc_us_colemak),
	KBD_MAP(KB_US | KB_APPLE,	KB_US,	hidkbd_keydesc_apple),
	KBD_MAP(KB_JP,			KB_US,	hidkbd_keydesc_jp),
	KBD_MAP(KB_JP | KB_SWAPCTRLCAPS,KB_JP,	hidkbd_keydesc_swapctrlcaps),
	KBD_MAP(KB_DE,			KB_US,	hidkbd_keydesc_de),
	KBD_MAP(KB_DE | KB_NODEAD,	KB_DE,	hidkbd_keydesc_de_nodead),
	KBD_MAP(KB_FR,                  KB_US,  hidkbd_keydesc_fr),
	KBD_MAP(KB_FR | KB_SWAPCTRLCAPS,KB_FR,	hidkbd_keydesc_swapctrlcaps),
	KBD_MAP(KB_BEPO,                KB_US,  hidkbd_keydesc_fr_bepo),
	KBD_MAP(KB_BE,                  KB_FR,  hidkbd_keydesc_be),
	KBD_MAP(KB_BR,                  KB_US,  hidkbd_keydesc_br),
	KBD_MAP(KB_BR | KB_NODEAD,	KB_BR,  hidkbd_keydesc_br_nodead),
	KBD_MAP(KB_DK,			KB_US,	hidkbd_keydesc_dk),
	KBD_MAP(KB_DK | KB_NODEAD,	KB_DK,	hidkbd_keydesc_dk_nodead),
	KBD_MAP(KB_IS,			KB_US,	hidkbd_keydesc_is),
	KBD_MAP(KB_IS | KB_NODEAD,	KB_IS,	hidkbd_keydesc_is_nodead),
	KBD_MAP(KB_IT,			KB_US,	hidkbd_keydesc_it),
	KBD_MAP(KB_UK,			KB_US,	hidkbd_keydesc_uk),
	KBD_MAP(KB_UK | KB_SWAPCTRLCAPS,KB_UK,	hidkbd_keydesc_swapctrlcaps),
	KBD_MAP(KB_SV,			KB_DK,	hidkbd_keydesc_sv),
	KBD_MAP(KB_SV | KB_NODEAD,	KB_SV,	hidkbd_keydesc_sv_nodead),
	KBD_MAP(KB_EE,			KB_SV,	hidkbd_keydesc_ee),
	KBD_MAP(KB_EE | KB_NODEAD,	KB_EE,	hidkbd_keydesc_ee_nodead),
	KBD_MAP(KB_NEO,			KB_US,	hidkbd_keydesc_de_neo),
	KBD_MAP(KB_NO,			KB_DK,	hidkbd_keydesc_no),
	KBD_MAP(KB_NO | KB_NODEAD,	KB_NO,	hidkbd_keydesc_no_nodead),
	KBD_MAP(KB_ES ,			KB_US,	hidkbd_keydesc_es),
	KBD_MAP(KB_PT,			KB_US,	hidkbd_keydesc_pt),
	KBD_MAP(KB_SG,			KB_US,	hidkbd_keydesc_sg),
	KBD_MAP(KB_SG | KB_NODEAD,	KB_SG,	hidkbd_keydesc_sg_nodead),
	KBD_MAP(KB_SF,			KB_SG,	hidkbd_keydesc_sf),
	KBD_MAP(KB_SF | KB_NODEAD,	KB_SF,	hidkbd_keydesc_sg_nodead),
	KBD_MAP(KB_TR,			KB_US,	hidkbd_keydesc_tr),
	KBD_MAP(KB_TR | KB_NODEAD,	KB_TR,	hidkbd_keydesc_tr_nodead),
	KBD_MAP(KB_LA,			KB_US,	hidkbd_keydesc_la),
	KBD_MAP(KB_CF,			KB_US,	hidkbd_keydesc_cf),
	KBD_MAP(KB_PL,			KB_US,	hidkbd_keydesc_pl),
	KBD_MAP(KB_PL | KB_SWAPCTRLCAPS,KB_PL,	hidkbd_keydesc_swapctrlcaps),
	KBD_MAP(KB_HU,			KB_US,	hidkbd_keydesc_hu),
	{0, 0, 0, 0}
};

#undef KBD_MAP
#undef KC

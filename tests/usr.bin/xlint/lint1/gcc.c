/*	$NetBSD: gcc.c,v 1.6 2025/07/31 17:30:52 rillig Exp $	*/
# 3 "gcc.c"

/*
 * Miscellaneous tests that are specific to lint's GCC mode.
 */

/* lint1-extra-flags: -chaapbrz -X 351 */

// Before C99 introduced __func__, GCC already had __FUNCTION__ with the same
// semantics.
const char *
gcc_function(void)
{
	/* expect+1: error: negative array dimension (-13) [20] */
	typedef int size[-(int)sizeof __FUNCTION__];

	return __FUNCTION__;
}

// Before C99 introduced designators in initializers, GCC already had them,
// although with a different syntax for struct/union members and with the
// a...b for ranges of array elements.
int array_range_initializers[256] = {
	[2] = 1,
	[3] = 2,
	[4 ... 5] = 3
};

_Bool dbl_isinf(double);

// Test that the GCC '__extension__' and '__typeof' are recognized.
void
extension_and_typeof(void)
{
	double __logbw = 1;
	if (__extension__(({
		__typeof((__logbw)) x_ = (__logbw);
		!dbl_isinf((x_));
	})))
		__logbw = 1;
}

int
range_in_case_label(int i)
{
	switch (i) {
	case 1 ... 40:		// This is a GCC extension.
		return 1;
	default:
		return 2;
	}
}

union {
	int i;
	char *s;
} initialize_union_with_mixed_designators[] = {
	{ i: 1 },		/* GCC-style */
	{ s: "foo" },		/* GCC-style */
	{ .i = 1 },		/* C99-style */
	{ .s = "foo" }		/* C99-style */
};

union {
	int i[10];
	short s;
} initialize_union_with_gcc_designators[] = {
	{ s: 2 },
	{ i: { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 } },
};

void
declaration_of_variable_array(int i)
{
	int array[i];
	while (i-- > 0)
		array[i] = 0;
}

/*
 * Before cgram.y 1.226 from 2021-05-03, lint could not parse typeof(...) if
 * there was a statement before it.
 */
void *
typeof_after_statement(void **ptr)
{
	return ({
		if (*ptr != (void *)0)
			ptr++;
		__typeof__(*ptr) ret = *ptr;
		ret;
	});
}

const char *
auto_type(const char *ptr)
{
	__auto_type pp = &ptr;
	return *pp;
}

void
atomic_functions(void)
{
	static unsigned long long v, *pv;
	v = __atomic_load_n(pv, 0);
	v = __atomic_exchange_n(pv, 0, 0);
	v = __atomic_add_fetch(pv, 0, 0);
	v = __atomic_sub_fetch(pv, 0, 0);
	v = __atomic_and_fetch(pv, 0, 0);
	v = __atomic_xor_fetch(pv, 0, 0);
	v = __atomic_or_fetch(pv, 0, 0);
	v = __atomic_nand_fetch(pv, 0, 0);
	v = __atomic_fetch_add(pv, 0, 0);
	v = __atomic_fetch_sub(pv, 0, 0);
	v = __atomic_fetch_and(pv, 0, 0);
	v = __atomic_fetch_xor(pv, 0, 0);
	v = __atomic_fetch_or(pv, 0, 0);
	v = __atomic_fetch_nand(pv, 0, 0);

	static char c, *pc;
	c = __atomic_load_n(pc, 0);
	c = __atomic_exchange_n(pc, 0, 0);

	/* expect+1: warning: conversion from 'unsigned long long' to 'char' may lose accuracy [132] */
	c = __atomic_exchange_n(pv, 0, 0);
}

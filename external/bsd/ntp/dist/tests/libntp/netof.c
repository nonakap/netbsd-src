/*	$NetBSD: netof.c,v 1.4 2024/08/18 20:47:27 christos Exp $	*/

#include "config.h"

#include "ntp_stdlib.h"
#include "ntp_calendar.h"

#include "unity.h"

#include "sockaddrtest.h"


void setUp(void);
void test_ClassCAddress(void);
void test_IPv6Address(void);


void
setUp(void)
{
	init_lib();

	return;
}


void
test_ClassCAddress(void)
{
	sockaddr_u input = CreateSockaddr4("192.0.2.255", NTP_PORT);
	sockaddr_u expected = CreateSockaddr4("192.0.2.0", NTP_PORT);

	sockaddr_u* actual = netof(&input);

	TEST_ASSERT_TRUE(actual != NULL);
	TEST_ASSERT_TRUE(IsEqual(expected, *actual));

	return;
}


void
test_IPv6Address(void)
{
	/* IPv6 addresses are assumed to have 64-bit host- and 64-bit network parts. */
	const struct in6_addr input_address = { { {
		0x20, 0x01, 0x0d, 0xb8,
		0x85, 0xa3, 0x08, 0xd3, 
		0x13, 0x19, 0x8a, 0x2e,
		0x03, 0x70, 0x73, 0x34
	} } }; // 2001:0db8:85a3:08d3:1319:8a2e:0370:7334

	const struct in6_addr expected_address = { { {
		0x20, 0x01, 0x0d, 0xb8,
		0x85, 0xa3, 0x08, 0xd3, 
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	} } }; // 2001:0db8:85a3:08d3:0000:0000:0000:0000

	sockaddr_u input;
	memset(&input, 0, sizeof(input));
	input.sa6.sin6_family = AF_INET6;
	input.sa6.sin6_addr = input_address;
	SET_PORT(&input, 3000);

	sockaddr_u expected;
	memset(&expected, 0, sizeof(expected));
	expected.sa6.sin6_family = AF_INET6;
	expected.sa6.sin6_addr = expected_address;
	SET_PORT(&expected, 3000);

	sockaddr_u* actual = netof(&input);

	TEST_ASSERT_TRUE(actual != NULL);
	TEST_ASSERT_TRUE(IsEqual(expected, *actual));

	return;
}

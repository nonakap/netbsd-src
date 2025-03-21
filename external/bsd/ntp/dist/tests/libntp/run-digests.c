/*	$NetBSD: run-digests.c,v 1.2 2024/08/18 20:47:27 christos Exp $	*/

/* AUTOGENERATED FILE. DO NOT EDIT. */

//=======Test Runner Used To Run Each Test Below=====
#define RUN_TEST(TestFunc, TestLineNum) \
{ \
  Unity.CurrentTestName = #TestFunc; \
  Unity.CurrentTestLineNumber = TestLineNum; \
  Unity.NumberOfTests++; \
  if (TEST_PROTECT()) \
  { \
      setUp(); \
      TestFunc(); \
  } \
  if (TEST_PROTECT() && !TEST_IS_IGNORED) \
  { \
    tearDown(); \
  } \
  UnityConcludeTest(); \
}

//=======Automagically Detected Files To Include=====
#include "unity.h"
#include <setjmp.h>
#include <stdio.h>
#include "config.h"
#include "ntp.h"
#include "ntp_stdlib.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

//=======External Functions This Runner Calls=====
extern void setUp(void);
extern void tearDown(void);
extern void test_Digest_AES128CMAC(void);
extern void test_Digest_MD4(void);
extern void test_Digest_MD5(void);
extern void test_Digest_MDC2(void);
extern void test_Digest_RIPEMD160(void);
extern void test_Digest_SHA1(void);
extern void test_Digest_SHAKE128(void);
extern void test_Digest_DSA(void);
extern void test_Digest_DSA_SHA(void);
extern void test_Digest_SHA(void);


//=======Suite Setup=====
static void suite_setup(void)
{
extern int change_iobufs(int);
extern int change_logfile(const char*, int);
change_iobufs(1);
change_logfile("stderr", 0);
}

//=======Test Reset Option=====
void resetTest(void);
void resetTest(void)
{
  tearDown();
  setUp();
}

char const *progname;


//=======MAIN=====
int main(int argc, char *argv[])
{
  progname = argv[0];
  suite_setup();
  UnityBegin("digests.c");
  RUN_TEST(test_Digest_AES128CMAC, 131);
  RUN_TEST(test_Digest_MD4, 168);
  RUN_TEST(test_Digest_MD5, 205);
  RUN_TEST(test_Digest_MDC2, 238);
  RUN_TEST(test_Digest_RIPEMD160, 275);
  RUN_TEST(test_Digest_SHA1, 314);
  RUN_TEST(test_Digest_SHAKE128, 353);
  RUN_TEST(test_Digest_DSA, 390);
  RUN_TEST(test_Digest_DSA_SHA, 429);
  RUN_TEST(test_Digest_SHA, 468);

  return (UnityEnd());
}

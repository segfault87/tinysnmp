#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.63)
AC_INIT(tinysnmp, 0.1.0, mastermind@planetmono.org)
AM_INIT_AUTOMAKE(tinysnmp, 0.1.0)
AC_CONFIG_SRCDIR([src/tinysnmp.c])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdio.h stdlib.h unistd.h])
AC_CHECK_HEADERS(openssl/hmac.h openssl/evp.h openssl/aes.h openssl/des.h openssl/dh.h)

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC

AC_OUTPUT(Makefile src/Makefile)


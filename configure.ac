AC_INIT([sbsigntool], [0.9.4], [James.Bottomley@HansenPartnership.com])

AM_INIT_AUTOMAKE()

AC_PREREQ(2.60)

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_SRCDIR(src/sbsign.c)

AM_PROG_AS
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_RANLIB
AC_PROG_MKDIR_P

AC_CHECK_TOOL(OBJCOPY, [objcopy])
AC_CHECK_TOOL(STRIP, [strip])

 AC_CHECK_HEADER([bfd.h], [],
  AC_MSG_ERROR([bfd.h not found.]
[bfd.h is usually distributed in a binutils development package.]))

if test $cross_compiling = no; then
  AM_MISSING_PROG(HELP2MAN, help2man)
else
  HELP2MAN=:
fi

AC_MSG_CHECKING([build system endianness])
AC_PREPROC_IFELSE(
  [AC_LANG_PROGRAM([[#include <endian.h>]],
		   [[#if __BYTE_ORDER != __LITTLE_ENDIAN]]
		   [[#error]]
		   [[#endif]])],
  endian=little
  little_endian=1
  big_endian=0)

AC_PREPROC_IFELSE(
  [AC_LANG_PROGRAM([[#include <endian.h>]],
		   [[#if __BYTE_ORDER != __BIG_ENDIAN]]
		   [[#error]]
		   [[#endif]])],
  endian=big
  little_endian=0
  big_endian=1)


if test x"$endian" != "xbig" -a x"$endian" != "xlittle"; then
  AC_MSG_ERROR([Can't determine endianness; is endian.h present?])
fi
AC_MSG_RESULT($endian)
AC_DEFINE_UNQUOTED(HAVE_LITTLE_ENDIAN, $little_endian, [Little-endian system])
AC_DEFINE_UNQUOTED(HAVE_BIG_ENDIAN, $big_endian, [Big-endian system])

PKG_PROG_PKG_CONFIG()
PKG_CHECK_MODULES(libcrypto, libcrypto,
    [],
    AC_MSG_ERROR([libcrypto (from the OpenSSL package) is required]))

PKG_CHECK_MODULES(uuid, uuid,
    [],
    AC_MSG_ERROR([libuuid (from the uuid package) is required]))

dnl gnu-efi headers require extra include dirs
EFI_ARCH=$(uname -m | sed 's/i.86/ia32/;s/arm.*/arm/')
AM_CONDITIONAL(TEST_BINARY_FORMAT, [ test "$EFI_ARCH" = "arm" -o "$EFI_ARCH" = "aarch64" ])

##
# no consistent view of where gnu-efi should dump the efi stuff, so find it
##
for path in /lib /lib64 /usr/lib /usr/lib64 /usr/lib32 /lib/efi /lib64/efi /usr/lib/efi /usr/lib64/efi /usr/lib/gnuefi /usr/lib64/gnuefi ; do
    if test -e $path/crt0-efi-$EFI_ARCH.o; then
       CRTPATH=$path
    fi
done
if test -z "$CRTPATH"; then
   AC_MSG_ERROR([cannot find the gnu-efi crt path])
fi

EFI_CPPFLAGS="-I/usr/include/efi -I/usr/include/efi/$EFI_ARCH \
 -DEFI_FUNCTION_WRAPPER"
CPPFLAGS_save="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $EFI_CPPFLAGS"
AC_CHECK_HEADERS([efi.h], [], [], $EFI_INCLUDES)
CPPFLAGS="$CPPFLAGS_save"
AC_SUBST(EFI_CPPFLAGS, $EFI_CPPFLAGS)
AC_SUBST(EFI_ARCH, $EFI_ARCH)
AC_SUBST(CRTPATH, $CRTPATH)

AC_CONFIG_FILES([Makefile src/Makefile lib/ccan/Makefile]
		[docs/Makefile tests/Makefile])
AC_OUTPUT

dnl
dnl MeshVPN - A open source peer-to-peer VPN (forked from PeerVPN)
dnl
dnl Copyright (C) 2016  Tobias Volk <mail@tobiasvolk.de>
dnl Copyright (C) 2016       Hideman Developer <company@hideman.net>
dnl Copyright (C) 2017  Benjamin Kübler <b.kuebler@kuebler-it.de>
dnl
dnl This program is free software: you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation, either version 3 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program.  If not, see <http://www.gnu.org/licenses/>.
dnl
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])

AC_INIT([MeshVPN], [1.1.0-alpha.1], [b.kuebler@kuebler-it.de])

# Platform specific settings
AC_CANONICAL_HOST
case $host_os in
  darwin* )
        # Do something specific for mac
        LDFLAGS="-L/usr/local/opt/libressl/lib $LDFLAGS"
        CPPFLAGS="-I/usr/local/opt/libressl/include $CPPFLAGS"
        ;;
  linux*)
        # Do something specific for linux
        ;;
   *BSD*)
        # Do something specific for BSD
        ;;
    *)
        #Default Case
        AC_MSG_ERROR([Your platform is not currently supported])
        ;;
esac

AC_DEFINE_UNQUOTED([TARGET_ALIAS], ["${host}"], [A string representing our host])

# add include dir for header files
CPPFLAGS="$CPPFLAGS -I../include"

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([z], [compress])
AC_CHECK_LIB([ssl], [SSL_library_init]) # old openssl or compatible library like libressl
AC_CHECK_LIB([ssl], [OPENSSL_init_ssl]) # we have openssl also newer version
AC_CHECK_LIB([crypto], [ENGINE_init])
AC_CHECK_LIB([seccomp], [seccomp_init])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h stdio.h unistd.h stdint.h string.h time.h signal.h])
AC_CHECK_HEADERS([syslog.h fcntl.h seccomp.h netdb.h net/if.h netinet/in.h])
AC_CHECK_HEADERS([sys/types.h sys/stat.h sys/ioctl.h sys/select.h sys/socket.h])
AC_CHECK_HEADERS([grp.h pwd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset select socket])

# Sanity check for configure
AC_CONFIG_SRCDIR([src/meshvpn.c])

# Also initialize automake
AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects])

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([
  Makefile
  src/Makefile])

AC_OUTPUT


#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6048
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33411);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-6048: glib2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6048 (glib2)");
 script_set_attribute(attribute: "description", value: "GLib is the low-level core library that forms the basis
for projects such as GTK+ and GNOME. It provides data structure
handling for C, portability wrappers, and interfaces for such runtime
functionality as an event loop, threads, dynamic loading, and an
object system.

This package provides version 2 of GLib.

-
Update Information:

>From the release announcement:    * Update to PCRE 7.7   - fix a heap-based
buffer overflow in PCRE (CVE-2008-2371)    * Bug fixes:   528752 Win32 build an
d
SSL not working   539074 Cannot get exit status with g_spawn_command_line_sync(
)
316221 G_LOCK warns about breaking strict-aliasing rules   519137 g_slice_dup
macro needs cast for 64-bit platform   536158 also bump GHashTable version when
a node is removed via
g_hash_table_iter_remove()/g_hash_table_iter_steal()   529321 make check fails
in glib/pcre   314453 Nautilus crashes in Solaris when browsing the attached
file   502511 g_assert_cmphex prints invalid message   538119 glib's mainloop
leaks a pipe to sub-processes   540459 there are no way of getting the real
number of bytes         written in GMemoryOutputStream   540423 unrecoverable
error after g_seekable_truncate(seekable,0,...)   530196
_g_local_file_has_trash_dir() doesn't handle st_dev == 0   528600
g_dummy_file_get_parent('scheme://example.com/')   536641 Filesystem querying i
n
gio does not list AFS and autofs         file systems   537392 Additional colon
in xattr name   528433 gdesktopappinfo snafu ...   526320 should not list mount
s
that the user doesn't have permiss...   527132 nautilus crash when making ftp
connection   532852 totem_pl_parser_parse_with_base: assertion `...   459905 Bu
g
in wcwidth data   534085 g_unichar_iswide_cjk() has a totally wrong table    *
Updated translations:   Bulgarian (bg)   German (de)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2371");
script_summary(english: "Check for the version of the glib2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"glib2-2.16.4-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

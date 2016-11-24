
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3979
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32460);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-3979: libpng10");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3979 (libpng10)");
 script_set_attribute(attribute: "description", value: "The libpng10 package contains an old version of libpng, a library of functions
for creating and manipulating PNG (Portable Network Graphics) image format
files.

This package is needed if you want to run binaries that were linked dynamically
with libpng 1.0.x.

-
Update Information:

This update fixes the way that libpng10 handles unknown zero-length chunks,
which in previous versions could result in writing to attacker controlled
addresses, depending on how the libpng api is used.    To be affected, an
application would have to call png_set_keep_unknown_chunks(), which tells libpn
g
not to ignore unknown chunks, but to do something with them.  The PNG spec
allows for 'unknown' chunks, which are ignored by default, but an  application
could in theory embed some sort of extra data in a png image, then later get it
back out via this mechanism.    No packages in Fedora are believed to be
affected by this issue, but it's possible that third-party applications could
be.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-2445", "CVE-2007-5269", "CVE-2008-1382");
script_summary(english: "Check for the version of the libpng10 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libpng10-1.0.37-1.fc7", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

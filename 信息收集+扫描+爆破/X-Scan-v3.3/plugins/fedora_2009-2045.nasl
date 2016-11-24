
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2045
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35808);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-2045: libpng10");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2045 (libpng10)");
 script_set_attribute(attribute: "description", value: "The libpng10 package contains an old version of libpng, a library of functions
for creating and manipulating PNG (Portable Network Graphics) image format
files.

This package is needed if you want to run binaries that were linked dynamically
with libpng 1.0.x.

-
Update Information:

This release fixes a vulnerability in which some arrays of pointers are not
initialized prior to using malloc to define the pointers. If the application
runs out of memory while executing the allocation loop (which can be forced by
malevolent input), libpng10 will jump to a cleanup process that attempts to fre
e
all of the pointers, including the undefined ones.    This issue has been
assigned CVE-2009-0040
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1382", "CVE-2009-0040");
script_summary(english: "Check for the version of the libpng10 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libpng10-1.0.43-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

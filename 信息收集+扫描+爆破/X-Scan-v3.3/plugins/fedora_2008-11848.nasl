
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-11848
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37013);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2008-11848: libcdaudio");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-11848 (libcdaudio)");
 script_set_attribute(attribute: "description", value: "libcdaudio is a library designed to provide functions to control
operation of a CD-ROM when playing audio CDs.  It also contains
functions for CDDB and CD Index lookup.

-
Update Information:

This update fixes a potential buffer overflow caused by large amount of CDDB
replies (CVE-2005-0706).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2005-0706");
script_summary(english: "Check for the version of the libcdaudio package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libcdaudio-0.99.12p2-11.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

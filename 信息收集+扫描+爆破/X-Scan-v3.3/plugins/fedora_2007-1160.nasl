
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1160
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27704);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1160: centericq");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1160 (centericq)");
 script_set_attribute(attribute: "description", value: "Centericq is a text mode menu- and window-driven IM interface that supports the
ICQ2000, Yahoo!, AIM, MSN, IRC and Jabber protocols.

-
ChangeLog:


Update information :

* Thu Jul 19 2007 Andreas Bierfert <andreas.bierfert[AT]lowlatency.de>
- 4.21.0-13
- fix CVE-2007-3713 multiple buffer overflows (#247979) with help from
Lubomir Kundrak
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3713");
script_summary(english: "Check for the version of the centericq package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"centericq-4.21.0-13.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1977
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27741);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1977: vavoom");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1977 (vavoom)");
 script_set_attribute(attribute: "description", value: "Vavoom is an enhanced open-source port of Doom. Allowing you to play not only
the classic 3D first-person shooter Doom, but also the Doom derived classics
Heretic, Hexen and Strife. Compared to the original games it adds extra
features such as translucency and freelook support and ofcourse the capability
to play these classics under Linux.

-
Update Information:

Security update fixing various format strings vulnerabilities and a DOS vulnera
bility in the vavoom server, this fixes: CVE-2007-4533, CVE-2007-4534 & CVE-200
7-4535. Also see bugzilla bug 256621.

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-4533", "CVE-2007-4534", "CVE-2007-4535");
script_summary(english: "Check for the version of the vavoom package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"vavoom-1.24-3.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

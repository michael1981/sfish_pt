
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-8928
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34452);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-8928: jhead");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-8928 (jhead)");
 script_set_attribute(attribute: "description", value: "Jhead displays and manipulates the non-image portions of EXIF formatted
JPEG images, such as the images produced by most digital cameras.

-
ChangeLog:


Update information :

* Thu Oct 16 2008 Adrian Reber <adrian lisas de> - 2.84-1
- updated to 2.84
- fixes 'CVE-2008-4575 jhead buffer overflow' (#467262)
- removed upstreamed makefile patch
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-4575");
script_summary(english: "Check for the version of the jhead package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"jhead-2.84-1.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

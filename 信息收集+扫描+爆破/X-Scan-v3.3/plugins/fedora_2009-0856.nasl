
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-0856
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35441);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-0856: DevIL");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-0856 (DevIL)");
 script_set_attribute(attribute: "description", value: "Developer's Image Library (DevIL) is a programmer's library to develop
applications with very powerful image loading capabilities, yet is easy for a
developer to learn and use. Ultimate control of images is left to the
developer, so unnecessary conversions, etc. are not performed. DevIL utilizes
a simple, yet powerful, syntax. DevIL can load, save, convert, manipulate,
filter and display a wide variety of image formats.

-
Update Information:

- Fix missing symbols (rh 480269)  - Fix off by one error in CVE-2008-5262 chec
k
(rh 479864)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5262");
script_summary(english: "Check for the version of the DevIL package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"DevIL-1.7.5-2.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

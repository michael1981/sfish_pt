
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6186
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33453);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-6186: WebKit");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6186 (WebKit)");
 script_set_attribute(attribute: "description", value: "WebKit is an open source web browser engine.

-
Update Information:

This updated WebKit snapshot fixes CVE-2008-2307. (A memory  corruption issue
exists in WebKit's handling of JavaScript  arrays. Visiting a maliciously
crafted website may lead to an  unexpected application termination or arbitrary
code execution.)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2307");
script_summary(english: "Check for the version of the WebKit package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"WebKit-1.0.0-0.11.svn34655.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

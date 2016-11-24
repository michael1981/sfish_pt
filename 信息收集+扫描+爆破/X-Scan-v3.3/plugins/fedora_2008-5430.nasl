
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-5430
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33222);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-5430: freetype");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-5430 (freetype)");
 script_set_attribute(attribute: "description", value: "The FreeType engine is a free and portable font rendering
engine, developed to provide advanced font support for a variety of
platforms and environments. FreeType is a library which can open and
manages font files as well as efficiently load, hint and render
individual glyphs. FreeType is not a font server or a complete
text-rendering library.

-
Update Information:

This update backports security fixes from upstream version 2.3.6 -
CVE-2008-1806, CVE-2008-1807 and CVE-2008-1808.    For further details, see:
[9]http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=715
[10]http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=716
[11]http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=717
Note: TTF bytecode interpreter is not enabled by default in the Fedora freetype
packages, therefore Fedora packages were not affected by the TTF part of the
CVE-2008-1808.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");
script_summary(english: "Check for the version of the freetype package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"freetype-2.3.5-4.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7012
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34172);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-7012: poppler");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7012 (poppler)");
 script_set_attribute(attribute: "description", value: "Poppler, a PDF rendering library, is a fork of the xpdf PDF
viewer developed by Derek Noonburg of Glyph and Cog, LLC.

-
Update Information:

Security fix:  Add upstream patch for CVE-2008-2950 / oCERT-2008-007 - use of
an uninitialized pointer to call free() in Page::~Page (#454277)
[9]http://www.ocert.org/advisories/ocert-2008-007.html    Bug fixes:  Fix crash
when reading QuadPoints (#448516)  Use static FT_Library in CairoOutputDev, as
dynamic may trigger  use-after-free and crash e.g. evince (#456867)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2950");
script_summary(english: "Check for the version of the poppler package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"poppler-0.8.1-2.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

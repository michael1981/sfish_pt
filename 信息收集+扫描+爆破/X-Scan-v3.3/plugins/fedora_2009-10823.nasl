
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10823
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42279);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-10823: poppler");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10823 (poppler)");
 script_set_attribute(attribute: "description", value: "Poppler, a PDF rendering library, is a fork of the xpdf PDF
viewer developed by Derek Noonburg of Glyph and Cog, LLC.

-
Update Information:

This build addresses several recent security issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3606", "CVE-2009-3607", "CVE-2009-3608", "CVE-2009-3609");
script_summary(english: "Check for the version of the poppler package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"poppler-0.8.7-7.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

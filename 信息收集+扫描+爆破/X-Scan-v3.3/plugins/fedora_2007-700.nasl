
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-700
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(26082);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2007-700: openoffice.org");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-700 (openoffice.org)");
 script_set_attribute(attribute: "description", value: "OpenOffice.org is an Open Source, community-developed, multi-platform
office productivity suite.  It includes the key desktop applications,
such as a word processor, spreadsheet, presentation manager, formula
editor and drawing program, with a user interface and feature set
similar to other office suites.  Sophisticated and flexible,
OpenOffice.org also works transparently with a variety of file
formats, including Microsoft Office.

Usage: Simply type 'ooffice' to run OpenOffice.org or select the
requested component (Writer, Calc, Draw, Impress, etc.) from your
desktop menu. On first start a few files will be installed in the
user's home, if necessary.

The OpenOffice.org team hopes you enjoy working with OpenOffice.org!

Update Information:

This security updates addresses CVE-2007-2834 a flaw in
how openoffice.org handles corrupt TIFF graphic format file
headers
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-2834");
script_summary(english: "Check for the version of the openoffice.org package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"openoffice.org-2.0.4-5.5.24", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

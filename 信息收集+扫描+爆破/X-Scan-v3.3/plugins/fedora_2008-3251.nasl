
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3251
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32042);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-3251: openoffice.org");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3251 (openoffice.org)");
 script_set_attribute(attribute: "description", value: "OpenOffice.org is an Open Source, community-developed, multi-platform
office productivity suite.  It includes the key desktop applications,
such as a word processor, spreadsheet, presentation manager, formula
editor and drawing program, with a user interface and feature set
similar to other office suites.  Sophisticated and flexible,
OpenOffice.org also works transparently with a variety of file
formats, including Microsoft Office.

Usage: Simply type 'ooffice' to run OpenOffice.org or select the
requested component (Writer, Calc, Impress, etc.) from your
desktop menu. On first start a few files will be installed in the
user's home, if necessary.

-
Update Information:

Following security issues were addressed in this update:    #
CVE-2007-5745/5747: Manipulated Quattro Pro files can lead to heap overflows an
d
arbitrary code execution  # CVE-2007-5746: Manipulated EMF files can lead to
heap overflows and arbitrary code execution  # CVE-2008-0320: Manipulated OLE
files can lead to heap overflows and arbitrary code execution
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-4575", "CVE-2007-5745", "CVE-2007-5746", "CVE-2007-5747", "CVE-2008-0320");
script_summary(english: "Check for the version of the openoffice.org package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"openoffice.org-2.3.0-6.14.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

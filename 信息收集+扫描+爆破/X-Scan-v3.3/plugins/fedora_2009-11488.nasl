
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-11488
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42804);
 script_version("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-11488: qt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-11488 (qt)");
 script_set_attribute(attribute: "description", value: "Qt is a software toolkit for developing applications.

This package contains base tools, like string, xml, and network
handling.

-
Update Information:

A security flaw was found in the WebKit's Cross-Origin Resource Sharing (CORS)
implementation.    Multiple security flaws (integer underflow, invalid pointer
dereference, buffer underflow and a denial of service) were found in the way
WebKit's FTP parser used to process remote FTP directory listings.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1725", "CVE-2009-2700", "CVE-2009-2816", "CVE-2009-3384");
script_summary(english: "Check for the version of the qt package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"qt-4.5.3-9.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

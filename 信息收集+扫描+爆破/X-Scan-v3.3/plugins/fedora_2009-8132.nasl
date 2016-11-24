
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8132
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40452);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 11 2009-8132: OpenEXR");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8132 (OpenEXR)");
 script_set_attribute(attribute: "description", value: "OpenEXR is a high dynamic-range (HDR) image file format developed by Industrial
Light & Magic for use in computer imaging applications. This package contains
libraries and sample applications for handling the format.

-
ChangeLog:


Update information :

* Wed Jul 29 2009 Rex Dieter <rdieter fedoraproject org> 1.6.1-8
- CVE-2009-1720 OpenEXR: Multiple integer overflows (#513995)
- CVE-2009-1721 OpenEXR: Invalid pointer free by image decompression (#514003)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1720", "CVE-2009-1721");
script_summary(english: "Check for the version of the OpenEXR package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"OpenEXR-1.6.1-8.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

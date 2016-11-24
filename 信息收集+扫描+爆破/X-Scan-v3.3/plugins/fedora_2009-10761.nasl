
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10761
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42275);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-10761: jasper");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10761 (jasper)");
 script_set_attribute(attribute: "description", value: "This package contains an implementation of the image compression
standard JPEG-2000, Part 1. It consists of tools for conversion to and
from the JP2 and JPC formats.

-
ChangeLog:


Update information :

* Tue Oct 13 2009 Rex Dieter <rdieter fedoraproject org> - 1.900.1-13
- CVE-2008-3520 jasper: multiple integer overflows in jas_alloc calls (#461476)
- CVE-2008-3522 jasper: possible buffer overflow in
jas_stream_printf() (#461478)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3520", "CVE-2008-3522");
script_summary(english: "Check for the version of the jasper package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"jasper-1.900.1-13.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

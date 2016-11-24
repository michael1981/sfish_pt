
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3920
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32344);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-3920: perl-Imager");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3920 (perl-Imager)");
 script_set_attribute(attribute: "description", value: "Imager is a module for creating and altering images. It can read and
write various image formats, draw primitive shapes like lines,and
polygons, blend multiple images together in various ways, scale, crop,
render text and more.

-
ChangeLog:


Update information :

* Thu Apr 24 2008 Steven Pritchard <steve kspei com> 0.64-2
- Rebuild.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1928");
script_summary(english: "Check for the version of the perl-Imager package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"perl-Imager-0.64-2.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

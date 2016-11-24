
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-1289
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37680);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-1289: gnumeric");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-1289 (gnumeric)");
 script_set_attribute(attribute: "description", value: "Gnumeric is a spreadsheet program for the GNOME GUI desktop
environment.

-
ChangeLog:


Update information :

* Fri Jan 30 2009 Huzaifa Sidhpurwala <huzaifas redhat com> 1:1.8.2-6
- Resolves CVE-2008-5983
- Version bump to match the rawhide version
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5983", "CVE-2009-0318");
script_summary(english: "Check for the version of the gnumeric package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gnumeric-1.8.2-6.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

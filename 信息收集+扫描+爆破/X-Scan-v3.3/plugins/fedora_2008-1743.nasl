
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-1743
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31108);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-1743: scponly");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-1743 (scponly)");
 script_set_attribute(attribute: "description", value: "scponly is an alternative 'shell' for system administrators
who would like to provide access to remote users to both
read and write local files without providing any remote
execution priviledges. Functionally, it is best described
as a wrapper to the 'tried and true' ssh suite of applications.

-
ChangeLog:


Update information :

* Wed Feb 13 2008 Tomas Hoger <thoger redhat com> - 4.6-10
- Add patch to prevent restriction bypass using OpenSSH's scp options -F
and -o (CVE-2007-6415, #426072)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-6350", "CVE-2007-6415");
script_summary(english: "Check for the version of the scponly package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"scponly-4.6-10.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

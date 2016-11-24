
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8789
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40674);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-8789: kobo");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8789 (kobo)");
 script_set_attribute(attribute: "description", value: "Kobo is a set of python modules designed for rapid tools development.

-

This update can be installed with the 'yum' update program.  Use
su -c 'yum update kobo' at the command line.
For more information, refer to 'Managing Software with yum',
available at [9]http://docs.fedoraproject.org/yum/.

All packages are signed with the Fedora Project GPG key.  More details on the
GPG keys used by the Fedora Project can be found at
[10]http://fedoraproject.org/keys
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the kobo package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kobo-0.1.2-1.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

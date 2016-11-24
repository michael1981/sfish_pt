
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2362
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31429);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-2362: horde");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2362 (horde)");
 script_set_attribute(attribute: "description", value: "The Horde Framework provides a common structure and interface for Horde
applications (such as IMP, a web-based mail program). This RPM is
required for all other Horde module RPMs.

The Horde Project writes web applications in PHP and releases them under
Open Source licenses. For more information (including help with Horde
and its modules) please visit [9]http://www.horde.org/.

READ /usr/share/doc/horde-3.1.7/README.Fedora AFTER INSTALLING FOR
INSTRUCTIONS AND SECURITY!

For additional functionality, also install horde-enhanced

-
Update Information:

Fix arbitrary file inclusion through abuse of the theme preference.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the horde package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"horde-3.1.7-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

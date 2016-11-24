
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-0589
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27671);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2007-0589: denyhosts");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-0589 (denyhosts)");
 script_set_attribute(attribute: "description", value: "DenyHosts is a Python script that analyzes the sshd server log
messages to determine which hosts are attempting to hack into your
system. It also determines what user accounts are being targeted. It
keeps track of the frequency of attempts from each host and, upon
discovering a repeated attack host, updates the /etc/hosts.deny file
to prevent future break-in attempts from that host.  Email reports can
be sent to a system admin.

-
Update Information:

Low-impact fix resolving a DOS issue.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the denyhosts package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"denyhosts-2.6-5.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

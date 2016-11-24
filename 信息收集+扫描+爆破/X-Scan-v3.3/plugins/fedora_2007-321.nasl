
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-321
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24795);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 5 2007-321: ekiga");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-321 (ekiga)");
 script_set_attribute(attribute: "description", value: "GnomeMeeting is a tool to communicate with video and audio over the internet.
It uses the the standard SIP and H323 protocols.

Update Information:

Format string flaws were found in the way Ekiga processes
certain messages. If a user is running Ekiga, a remote
attacker who can connect to Ekiga could trigger this flaw
and potentially execute arbitrary code with the
privileges of the user.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the ekiga package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ekiga-2.0.1-5", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

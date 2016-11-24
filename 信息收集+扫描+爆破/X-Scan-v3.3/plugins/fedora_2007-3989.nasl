
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-3989
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(29195);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2007-3989: wesnoth");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-3989 (wesnoth)");
 script_set_attribute(attribute: "description", value: "The Battle for Wesnoth is a turn-based strategy game with a fantasy theme.

Build up a great army, gradually turning raw recruits into hardened
veterans. In later games, recall your toughest warriors and form a deadly
host against whom none can stand. Choose units from a large pool of
specialists, and hand-pick a force with the right strengths to fight well
on different terrains against all manner of opposition.

Fight to regain the throne of Wesnoth, of which you are the legitimate
heir, or use your dread power over the Undead to dominate the land of
mortals, or lead your glorious Orcish tribe to victory against the humans
who dared despoil your lands. Wesnoth has many different sagas waiting to
be played out. You can create your own custom units, and write your own
scenarios--or even full-blown campaigns. You can also challenge your
friends--or strangers--and fight multi-player epic fantasy battles.

-
Update Information:

Update to 1.2.8. Fixes #405661 (CVE-2007-5742)

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5742");
script_summary(english: "Check for the version of the wesnoth package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"wesnoth-1.2.8-2.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

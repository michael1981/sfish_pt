
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7761
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34174);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-7761: bitlbee");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7761 (bitlbee)");
 script_set_attribute(attribute: "description", value: "Bitlbee is an IRC to other chat networks gateway. Bitlbee can be used as
an IRC server which forwards everything you say to people on other chat
networks like ICQ, MSN, Jabber or Yahoo!

-
Update Information:

Upstream released Bitlbee 1.2.3 with the following changes to the former
release:    - Fixed one more flaw similar to the previous hijacking bug, caused
by inconsistent handling of the USTATUS_IDENTIFIED state. All code touching
these variables was reviewed and should be correct now.    Finished 7 Sep 2008
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the bitlbee package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"bitlbee-1.2.3-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

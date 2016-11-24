
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7274
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34102);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2008-7274: bitlbee");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7274 (bitlbee)");
 script_set_attribute(attribute: "description", value: "Bitlbee is an IRC to other chat networks gateway. Bitlbee can be used as
an IRC server which forwards everything you say to people on other chat
networks like ICQ, MSN, Jabber or Yahoo!

-
Update Information:

Upstream released Bitlbee 1.2.2 with the following changes to the former
release:    - Security bugfix: It was possible to hijack accounts (without
gaining access to the old account, it's simply an overwrite)  - Some more
stability improvements.  - Fixed bug where people with non-lowercase nicks
couldn't drop their account.  - Easier upgrades of non-forking daemon mode
servers (using the DEAF command).  - Can be cross-compiled for Win32 now! (No
support for SSL yet though, which makes it less useful for now.)  - Exponential
backoff on auto-reconnect.  - Changing passwords gives less confusing feedback
('password is empty') now.    Finished 26 Aug 2008
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

if ( rpm_check( reference:"bitlbee-1.2.2-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

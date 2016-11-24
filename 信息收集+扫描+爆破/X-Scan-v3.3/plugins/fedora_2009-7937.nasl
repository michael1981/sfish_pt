
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-7937
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40356);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-7937: znc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-7937 (znc)");
 script_set_attribute(attribute: "description", value: "ZNC is an IRC bouncer with many advanced features like detaching,
multiple users, per channel playback buffer, SSL, IPv6, transparent
DCC bouncing, Perl and C++ module support to name a few.

-
Update Information:

No CVE yet, one has been requested.    Upgrade to 0.072 of ZNC, fixes security
issue in bug 513152    An users data directory traversal flaw was found in the
way ZNC used to handle file upload requests via Direct Client Connection (DCC)
/dcc SEND messages. A remote IRC user could issue a /dcc SEND message with a
specially-crafted content (file to upload), which once accepted by a local,
unsuspecting ZNC user, would overwrite relevant files in the
users/<user>/downloads data directory.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the znc package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"znc-0.072-3.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

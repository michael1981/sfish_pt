
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-0917
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37071);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-0917: tor");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-0917 (tor)");
 script_set_attribute(attribute: "description", value: "Tor is a connection-based low-latency anonymous communication system.

Applications connect to the local Tor proxy using the SOCKS protocol. The
local proxy chooses a path through a set of relays, in which each relay
knows its predecessor and successor, but no others. Traffic flowing down
the circuit is unwrapped by a symmetric key at each relay, which reveals
the downstream relay.

Warnings: Tor does no protocol cleaning.  That means there is a danger
that application protocols and associated programs can be induced to
reveal information about the initiator. Tor depends on Privoxy and
similar protocol cleaners to solve this problem. This is alpha code,
and is even more likely than released code to have anonymity-spoiling
bugs. The present network is very small -- this further reduces the
strength of the anonymity provided. Tor is not presently suitable for
high-stakes anonymity.

-
Update Information:

New upstream release 0.2.0.33, with lots of bug fixes and one security fix:
[9]https://blog.torproject.org/blog/tor-0.2.0.33-stable-released
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the tor package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"tor-0.2.0.33-1.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

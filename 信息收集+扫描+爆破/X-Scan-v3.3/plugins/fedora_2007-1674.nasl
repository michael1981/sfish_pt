
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1674
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27726);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1674: tor");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1674 (tor)");
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


Update information :

* Fri Aug 03 2007 Enrico Scholz <enrico scholz informatik tu-chemnitz de> - 0.1
.2.16-1
- updated to 0.1.2.16 (SECURITY)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3165", "CVE-2007-4174");
script_summary(english: "Check for the version of the tor package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"tor-0.1.2.16-1.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

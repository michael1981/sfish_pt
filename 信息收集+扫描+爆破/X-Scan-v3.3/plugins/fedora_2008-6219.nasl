
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6219
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33457);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-6219: sipp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6219 (sipp)");
 script_set_attribute(attribute: "description", value: "SIPp is a free Open Source test tool / traffic generator for the SIP protocol.
It includes a few basic SipStone user agent scenarios (UAC and UAS) and
establishes and releases multiple calls with the INVITE and BYE methods. It
can also reads custom XML scenario files describing from very simple to
complex call flows. It features the dynamic display of statistics about
running tests (call rate, round trip delay, and message statistics), periodic
CSV statistics dumps, TCP and UDP over multiple sockets or multiplexed with
retransmission management and dynamically adjustable call rates.

-
Update Information:

CVE-2008-2085
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2085");
script_summary(english: "Check for the version of the sipp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"sipp-3.1-2.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

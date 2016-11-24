#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13698);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0183");
 
 name["english"] = "Fedora Core 1 2004-120: tcpdump";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-120 (tcpdump).

Tcpdump is a command-line tool for monitoring network traffic.
Tcpdump can capture and display the packet headers on a particular
network interface or on all interfaces.  Tcpdump can display all of
the packet headers, or just the ones that match particular criteria.


Install tcpdump if you need a program to monitor network traffic.

Update Information:


Tcpdump is a command-line tool for monitoring network traffic.

Tcpdump v3.8.1 and earlier versions contained multiple flaws in the
packet display functions for the ISAKMP protocol. Upon receiving
specially crafted ISAKMP packets, TCPDUMP would try to read beyond
the end of the packet capture buffer and subsequently crash.


Users of tcpdump are advised to upgrade to these erratum packages, which
contain backported security patches and are not vulnerable to these issues." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2004-120.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the tcpdump package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"tcpdump-3.7.2-8.fc1.2", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.7.2-8.fc1.2", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"arpwatch-2.1a11-8.fc1.2", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"tcpdump-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0183", value:TRUE);
}

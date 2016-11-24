
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2060
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27749);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-2060: snort");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2060 (snort)");
 script_set_attribute(attribute: "description", value: "Snort is a libpcap-based packet sniffer/logger which
can be used as a lightweight network intrusion detection system.
It features rules based logging and can perform protocol analysis,
content searching/matching and can be used to detect a variety of
attacks and probes, such as buffer overflows, stealth port scans,
CGI attacks, SMB probes, OS fingerprinting attempts, and much more.
Snort has a real-time alerting capabilty, with alerts being sent to syslog,
a separate 'alert' file, or as a WinPopup message via Samba's smbclient

Edit /etc/snort.conf to configure snort and use snort.d to start snort

This rpm is different from previous rpms and while it will not clobber
your current snortd file, you will need to modify it.

There are 9 different packages available

All of them require the base snort rpm.  Additionally, you will need
to chose a binary to install.

/usr/sbin/snort should end up being a symlink to a binary in one of
the following configurations:

plain      plain+flexresp
mysql      mysql+flexresp
postgresql postgresql+flexresp
snmp       snmp+flexresp
bloat      mysql+postgresql+flexresp+snmp

Please see the documentation in /usr/share/doc/snort-2.7.0.1

There are no rules in this package  the license  they are released under forbid
s
us from repackaging them  and redistributing them.

-
Update Information:

This build moves from manual linking to alternatives.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-5276");
script_summary(english: "Check for the version of the snort package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"snort-2.7.0.1-3.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

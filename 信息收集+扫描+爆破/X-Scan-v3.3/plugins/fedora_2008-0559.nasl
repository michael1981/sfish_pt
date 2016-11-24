
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-0559
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(30028);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-0559: syslog-ng");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-0559 (syslog-ng)");
 script_set_attribute(attribute: "description", value: "syslog-ng, as the name shows, is a syslogd replacement, but with new
functionality for the new generation. The original syslogd allows
messages only to be sorted based on priority/facility pairs; syslog-ng
adds the possibility to filter based on message contents using regular
expressions. The new configuration scheme is intuitive and powerful.
Forwarding logs over TCP and remembering all forwarding hops makes it
ideal for firewalled environments.

-
Update Information:

Contains a security fix for CVE-2007-6437/ZSA-2007-029 DoS
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-6437");
script_summary(english: "Check for the version of the syslog-ng package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"syslog-ng-2.0.7-1.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

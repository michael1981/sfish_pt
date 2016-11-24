
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-10879
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36373);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2008-10879: syslog-ng");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-10879 (syslog-ng)");
 script_set_attribute(attribute: "description", value: "syslog-ng, as the name shows, is a syslogd replacement, but with new
functionality for the new generation. The original syslogd allows
messages only to be sorted based on priority/facility pairs; syslog-ng
adds the possibility to filter based on message contents using regular
expressions. The new configuration scheme is intuitive and powerful.
Forwarding logs over TCP and remembering all forwarding hops makes it
ideal for firewalled environments.

-
Update Information:

Fixes CVE-2008-5110
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5110");
script_summary(english: "Check for the version of the syslog-ng package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"syslog-ng-2.0.10-1.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

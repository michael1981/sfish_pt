
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-1736
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35694);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-1736: fail2ban");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-1736 (fail2ban)");
 script_set_attribute(attribute: "description", value: "Fail2ban scans log files like /var/log/pwdfail or
/var/log/apache/error_log and bans IP that makes too many password
failures. It updates firewall rules to reject the IP address.

-
Update Information:

This updates fixes CVE-2009-0362. See     [9]http://cve.mitre.org/cgi-
bin/cvename.cgi?name=CVE-2009-0362    for further details.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0362");
script_summary(english: "Check for the version of the fail2ban package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"fail2ban-0.8.3-18.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

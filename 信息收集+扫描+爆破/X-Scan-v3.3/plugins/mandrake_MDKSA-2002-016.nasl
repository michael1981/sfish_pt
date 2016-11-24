
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13924);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2002:016-1: squid");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:016-1 (squid).");
 script_set_attribute(attribute: "description", value: "Three security issues were found in the 2.x versions of the Squid proxy
server up to and including 2.4.STABLE3. The first is a memory leak in
the optional SNMP interface to Squid which could allow a malicious user
who can send packets to the Squid SNMP port to possibly perform a
Denial of Service attack on ther server if the SNMP interface is
enabled. The next is a buffer overflow in the implementation of ftp://
URLs where allowed users could possibly perform a DoS on the server,
and may be able to trigger remote execution of code (which the authors
have not yet confirmed). The final issue is with the HTCP interface
which cannot be properly disabled from squid.conf; HTCP is enabled by
default on Mandrake Linux systems.
Update:
The squid updates for all versions other than Mandrake Linux were
incorrectly built with LDAP authentication which introduced a
dependency on OpenLDAP. These new packages do not use LDAP
authentication. The Single Network Firewall 7.2 package previously
released did not use LDAP authentication, however rebuilding the source
RPM package required LDAP to be installed. Single Network Firewall 7.2
users do not need to upgrade to these packages to have a properly
function squid.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:016-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the squid package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"squid-2.4.STABLE4-1.5mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-2.4.STABLE4-1.5mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-2.4.STABLE4-1.6mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

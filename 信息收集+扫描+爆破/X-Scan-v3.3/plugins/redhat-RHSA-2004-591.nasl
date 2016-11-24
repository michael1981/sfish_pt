
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15533);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-591: squid");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-591");
 script_set_attribute(attribute: "description", value: '
  An updated squid package that fixes a remote denial of service
  vulnerability
  is now avaliable.

  Squid is a full-featured Web proxy cache.

  iDEFENSE reported a flaw in the squid SNMP module. This flaw could allow
  an attacker who has the ability to send arbitrary packets to the SNMP port
  to restart the server, causing it to drop all open connections. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0918 to this issue.

  All users of squid should update to this erratum package, which contains a
  backport of the security fix for this vulnerability.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-591.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0918");
script_summary(english: "Check for the version of the squid packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"squid-2.4.STABLE7-1.21as", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-6.3E.2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

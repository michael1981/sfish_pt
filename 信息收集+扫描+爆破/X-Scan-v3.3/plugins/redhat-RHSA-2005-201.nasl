
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17340);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-201: squid");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-201");
 script_set_attribute(attribute: "description", value: '
  An updated squid package that fixes a denial of service issue is now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Squid is a full-featured Web proxy cache.

  A bug was found in the way Squid handles fully qualified domain name (FQDN)
  lookups. A malicious DNS server could crash Squid by sending a carefully
  crafted DNS response to an FQDN lookup. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-0446 to
  this issue.

  This erratum also includes two minor patches to the LDAP helpers. One
  corrects a slight malformation in ldap search requests (although all
  known LDAP servers accept the requests). The other adds documentation
  for the -v option to the ldap helpers.

  Users of Squid should upgrade to this updated package, which contains a
  backported patch, and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-201.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0446");
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

if ( rpm_check( reference:"squid-2.5.STABLE6-3.4E.5", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

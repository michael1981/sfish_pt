
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18500);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-415: squid");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-415");
 script_set_attribute(attribute: "description", value: '
  An updated squid package that fixes several security issues is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Squid is a full-featured Web proxy cache.

  A race condition bug was found in the way Squid handles the now obsolete
  Set-Cookie header. It is possible that Squid can leak Set-Cookie header
  information to other clients connecting to Squid. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-0626 to this issue. Please note that this issue only affected Red
  Hat Enterprise Linux 4.

  A bug was found in the way Squid handles PUT and POST requests. It is
  possible for an authorised remote user to cause a failed PUT or POST
  request which can cause Squid to crash. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-0718 to
  this issue.

  A bug was found in the way Squid processes errors in the access control
  list. It is possible that an error in the access control list could give
  users more access than intended. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2005-1345 to this issue.

  A bug was found in the way Squid handles access to the cachemgr.cgi script.
  It is possible for an authorised remote user to bypass access control
  lists with this flaw. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-1999-0710 to this issue.

  A bug was found in the way Squid handles DNS replies. If the port Squid
  uses for DNS requests is not protected by a firewall it is possible for a
  remote attacker to spoof DNS replies, possibly redirecting a user to
  spoofed or malicious content. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2005-1519 to this issue.

  Additionally this update fixes the following bugs:
  - LDAP Authentication fails with an assertion error when using Red Hat
  Enterprise Linux 4

  Users of Squid should upgrade to this updated package, which contains
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-415.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-1999-0710", "CVE-2005-0626", "CVE-2005-0718", "CVE-2005-1345", "CVE-2005-1519");
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

if ( rpm_check( reference:"squid-2.5.STABLE3-6.3E.13", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE6-3.4E.9", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

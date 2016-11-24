
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14595);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2004-350: krb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-350");
 script_set_attribute(attribute: "description", value: '
  Updated krb5 packages that improve client responsiveness and fix several
  security issues are now available for Red Hat Enterprise Linux 3.

  Kerberos is a networked authentication system that uses a trusted third
  party (a KDC) to authenticate clients and servers to each other.

  Several double-free bugs were found in the Kerberos 5 KDC and libraries. A
  remote attacker could potentially exploit these flaws to execuate arbitrary
  code. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the names CAN-2004-0642 and CAN-2004-0643 to these issues.

  A double-free bug was also found in the krb524 server (CAN-2004-0772),
  however this issue does not affect Red Hat Enterprise Linux 3 Kerberos
  packages.

  An infinite loop bug was found in the Kerberos 5 ASN.1 decoder library. A
  remote attacker may be able to trigger this flaw and cause a denial of
  service. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CAN-2004-0644 to this issue.

  When attempting to contact a KDC, the Kerberos libraries will iterate
  through the list of configured servers, attempting to contact each in turn.
  If one of the servers becomes unresponsive, the client will time out and
  contact the next configured server. When the library attempts to contact
  the next KDC, the entire process is repeated. For applications which must
  contact a KDC several times, the accumulated time spent waiting can become
  significant.

  This update modifies the libraries, notes which server for a given realm
  last responded to a request, and attempts to contact that server first
  before contacting any of the other configured servers.

  All users of krb5 should upgrade to these updated packages, which contain
  backported security patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-350.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0642", "CVE-2004-0643", "CVE-2004-0644");
script_summary(english: "Check for the version of the krb packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"krb5-devel-1.2.7-28", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.7-28", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.7-28", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.7-28", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

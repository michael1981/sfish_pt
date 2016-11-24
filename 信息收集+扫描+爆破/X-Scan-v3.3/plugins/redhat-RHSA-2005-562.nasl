
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18687);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2005-562: krb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-562");
 script_set_attribute(attribute: "description", value: '
  Updated krb5 packages which fix multiple security issues are now available
  for Red Hat Enterprise Linux 2.1 and 3.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  [Updated 26 Sep 2005]
  krb5-server packages have been added to this advisory for Red Hat
  Enterprise Linux 3 WS and Red Hat Enterprise Linux 3 Desktop.

  Kerberos is a networked authentication system which uses a trusted third
  party (a KDC) to authenticate clients and servers to each other.

  A double-free flaw was found in the krb5_recvauth() routine which may be
  triggered by a remote unauthenticated attacker. Although no exploit is
  currently known to exist, this issue could potentially be exploited to
  allow arbitrary code execution on a Key Distribution Center (KDC). The
  Common Vulnerabilities and Exposures project assigned the name
  CAN-2005-1689 to this issue.

  Daniel Wachdorf discovered a single byte heap overflow in the
  krb5_unparse_name() function, part of krb5-libs. Sucessful exploitation of
  this flaw would lead to a denial of service (crash). To trigger this flaw
  an attacker would need to have control of a kerberos realm that shares a
  cross-realm key with the target, making exploitation of this flaw unlikely.
  (CAN-2005-1175).

  Ga  l Delalleau discovered an information disclosure issue in the way
  some telnet clients handle messages from a server. An attacker could
  construct a malicious telnet server that collects information from the
  environment of any victim who connects to it using the Kerberos-aware
  telnet client (CAN-2005-0488).

  The rcp protocol allows a server to instruct a client to write to arbitrary
  files outside of the current directory. This could potentially cause a
  security issue if a user uses the Kerberos-aware rcp to copy files from a
  malicious server (CAN-2004-0175).

  All users of krb5 should update to these erratum packages which contain
  backported patches to correct these issues. Red Hat would like to thank
  the MIT Kerberos Development Team for their responsible disclosure of these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-562.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0175", "CVE-2005-0488", "CVE-2005-1175", "CVE-2005-1689");
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

if ( rpm_check( reference:"krb5-devel-1.2.2-37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.7-47", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.7-47", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.7-47", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.7-47", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17207);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-128: imap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-128");
 script_set_attribute(attribute: "description", value: '
  Updated imap packages to correct a security vulnerability in CRAM-MD5
  authentication are now available for Red Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The imap package provides server daemons for both the IMAP (Internet
  Message Access Protocol) and POP (Post Office Protocol) mail access
  protocols.

  A logic error in the CRAM-MD5 code in the University of Washington IMAP
  (UW-IMAP) server was discovered. When Challenge-Response Authentication
  Mechanism with MD5 (CRAM-MD5) is enabled, UW-IMAP does not properly enforce
  all the required conditions for successful authentication, which could
  allow remote attackers to authenticate as arbitrary users. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-0198 to this issue.

  All users of imap should upgrade to these updated packages, which contain a
  backported patch and are not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-128.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0198");
script_summary(english: "Check for the version of the imap packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"imap-2002d-11", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2002d-11", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imap-utils-2002d-11", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

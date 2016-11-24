
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35721);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0275: imap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0275");
 script_set_attribute(attribute: "description", value: '
  Updated imap packages to fix a security issue are now available for Red Hat
  Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The imap package provides server daemons for both the IMAP (Internet
  Message Access Protocol) and POP (Post Office Protocol) mail access
  protocols.

  A buffer overflow flaw was discovered in the dmail and tmail mail delivery
  utilities shipped with imap. If either of these utilities were used as a
  mail delivery agent, a remote attacker could potentially use this flaw to
  run arbitrary code as the targeted user by sending a specially-crafted mail
  message to the victim. (CVE-2008-5005)

  Users of imap should upgrade to these updated packages, which contain a
  backported patch to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0275.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-5005");
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

if ( rpm_check( reference:"imap-2002d-15", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2002d-15", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imap-utils-2002d-15", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

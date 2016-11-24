
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19990);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-527: openssh");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-527");
 script_set_attribute(attribute: "description", value: '
  Updated openssh packages that fix a security issue, bugs, and add support
  for recording login user IDs for audit are now available for Red Hat
  Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  OpenSSH is OpenBSD\'s SSH (Secure SHell) protocol implementation.

  An error in the way OpenSSH handled GSSAPI credential delegation was
  discovered. OpenSSH as distributed with Red Hat Enterprise Linux 4 contains
  support for GSSAPI user authentication, typically used for supporting
  Kerberos. On OpenSSH installations which have GSSAPI enabled, this flaw
  could allow a user who sucessfully authenticates using a method other than
  GSSAPI to be delegated with GSSAPI credentials. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CAN-2005-2798
  to this issue.

  Additionally, the following bugs have been addressed:

  The ssh command incorrectly failed when it was issued by the root user with
  a non-default group set.

  The sshd daemon could fail to properly close the client connection if
  multiple X clients were forwarded over the connection and the client
  session exited.

  The sshd daemon could bind only on the IPv6 address family for X forwarding
  if the port on IPv4 address family was already bound. The X forwarding did
  not work in such cases.

  This update also adds support for recording login user IDs for the auditing
  service. The user ID is attached to the audit records generated from the
  user\'s session.

  All users of openssh should upgrade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-527.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2798");
script_summary(english: "Check for the version of the openssh packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openssh-3.9p1-8.RHEL4.9", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-8.RHEL4.9", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.9", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.9p1-8.RHEL4.9", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.9p1-8.RHEL4.9", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

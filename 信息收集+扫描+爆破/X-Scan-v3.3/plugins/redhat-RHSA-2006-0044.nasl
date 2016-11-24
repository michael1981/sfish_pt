
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21030);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0044: openssh");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0044");
 script_set_attribute(attribute: "description", value: '
  Updated openssh packages that fix bugs in sshd and add auditing of user
  logins are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  OpenSSH is OpenBSD\'s SSH (Secure SHell) protocol implementation. This
  package includes the core files necessary for both the OpenSSH client and
  server.

  An arbitrary command execution flaw was discovered in the way scp copies
  files locally. It is possible for a local attacker to create a file with a
  carefully crafted name that could execute arbitrary commands as the user
  running scp to copy files locally. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) assigned the name CVE-2006-0225 to this issue.

  The following issue has also been fixed in this update:

  * If the sshd service was stopped using the sshd init script while the
  main sshd daemon was not running, the init script would kill other sshd
  processes, such as the running sessions. For example, this could happen
  when the \'service sshd stop\' command was issued twice.

  Additionally, this update implements auditing of user logins through the
  system audit service.

  All users of openssh should upgrade to these updated packages, which
  resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0044.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-0225");
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

if ( rpm_check( reference:"openssh-3.9p1-8.RHEL4.12", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-8.RHEL4.12", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.12", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.9p1-8.RHEL4.12", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.9p1-8.RHEL4.12", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

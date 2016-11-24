
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28237);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0703: openssh");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0703");
 script_set_attribute(attribute: "description", value: '
  Updated openssh packages that fix two security issues and various bugs are
  now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  OpenSSH is OpenBSD\'s SSH (Secure SHell) protocol implementation. These
  packages include the core files necessary for both the OpenSSH client and
  server.

  A flaw was found in the way the ssh server wrote account names to the
  audit subsystem. An attacker could inject strings containing parts of audit
  messages which could possibly mislead or confuse audit log parsing tools.
  (CVE-2007-3102)

  A flaw was found in the way the OpenSSH server processes GSSAPI
  authentication requests. When GSSAPI authentication was enabled in OpenSSH
  server, a remote attacker may have been able to determine if a username is
  valid. (CVE-2006-5052)

  The following bugs were also fixed:

  * the ssh daemon did not generate audit messages when an ssh session was
  closed.

  * GSSAPI authentication sometimes failed on clusters using DNS or
  load-balancing.

  * the sftp client and server leaked small amounts of memory in some cases.

  * the sftp client didn\'t properly exit and return non-zero status in batch
  mode when the destination disk drive was full.

  * when restarting the ssh daemon with the initscript, the ssh daemon was
  sometimes not restarted successfully because the old running ssh daemon was
  not properly killed.

  * with challenge/response authentication enabled, the pam sub-process was
  not terminated if the user authentication timed out.

  All users of openssh should upgrade to these updated packages, which
  contain patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0703.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-5052", "CVE-2007-3102");
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

if ( rpm_check( reference:"openssh-3.9p1-8.RHEL4.24", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-8.RHEL4.24", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.24", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.9p1-8.RHEL4.24", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.9p1-8.RHEL4.24", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

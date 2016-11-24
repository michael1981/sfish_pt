
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27829);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0540: openssh");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0540");
 script_set_attribute(attribute: "description", value: '
  Updated openssh packages that fix a security issue and various bugs are now
  available.

  This update has been rated as having moderate security impact by the Red Hat
  Security Response Team.

  OpenSSH is OpenBSD\'s SSH (Secure SHell) protocol implementation. These
  packages include the core files necessary for both the OpenSSH client and
  server.

  A flaw was found in the way the ssh server wrote account names to the audit
  subsystem. An attacker could inject strings containing parts of audit
  messages, which could possibly mislead or confuse audit log parsing tools.
  (CVE-2007-3102)

  A flaw was found in the way the OpenSSH server processes GSSAPI
  authentication requests. When GSSAPI authentication was enabled in the
  OpenSSH server, a remote attacker was potentially able to determine if a
  username is valid. (CVE-2006-5052)

  The following bugs in SELinux MLS (Multi-Level Security) support has also
  been fixed in this update:

  * It was sometimes not possible to select a SELinux role and level when
  logging in using ssh.

  * If the user obtained a non-default SELinux role or level, the role change
  was not recorded in the audit subsystem.

  * In some cases, on labeled networks, sshd allowed logins from level ranges
  it should not allow.

  The updated packages also contain experimental support for using private
  keys stored in PKCS#11 tokens for client authentication. The support is
  provided through the NSS (Network Security Services) library.

  All users of openssh should upgrade to these updated packages, which
  contain patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0540.html");
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

if ( rpm_check( reference:"openssh-4.3p2-24.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.3p2-24.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-4.3p2-24.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-server-4.3p2-24.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27831);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0555: pam");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0555");
 script_set_attribute(attribute: "description", value: '
  Updated pam packages that fix two security flaws, resolve several bugs, and
  add enhancements are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Pluggable Authentication Modules (PAM) provide a system whereby
  administrators can set up authentication policies without having to
  recompile programs that handle authentication.

  A flaw was found in the way pam_console set console device permissions. It
  was possible for various console devices to retain ownership of the console
  user after logging out, possibly leaking information to another local user.
  (CVE-2007-1716)

  A flaw was found in the way the PAM library wrote account names to the
  audit subsystem. An attacker could inject strings containing parts of audit
  messages which could possibly mislead or confuse audit log parsing tools.
  (CVE-2007-3102)

  As well, these updated packages fix the following bugs:

  * truncated MD5-hashed passwords in "/etc/shadow" were treated as valid,
  resulting in insecure and invalid passwords.

  * the pam_namespace module did not convert context names to raw format and
  did not unmount polyinstantiated directories in some cases. It also crashed
  when an unknown user name was used in "/etc/security/namespace.conf", the
  pam_namespace configuration file.

  * the pam_selinux module was not relabeling the controlling tty correctly,
  and in some cases it did not send complete information about user role and
  level change to the audit subsystem.

  These updated packages add the following enhancements:

  * pam_limits module now supports parsing additional config files placed
  into the /etc/security/limits.d/ directory. These files are read after the
  main configuration file.

  * the modules pam_limits, pam_access, and pam_time now send a message to
  the audit subsystem when a user is denied access based on the number of
  login sessions, origin of user, and time of login.

  * pam_unix module security properties were improved. Functionality in the
  setuid helper binary, unix_chkpwd, which was not required for user
  authentication, was moved to a new non-setuid helper binary, unix_update.

  All users of PAM should upgrade to these updated packages, which resolve
  these issues and add these enhancements.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0555.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1716", "CVE-2007-3102");
script_summary(english: "Check for the version of the pam packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pam-0.99.6.2-3.26.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pam-devel-0.99.6.2-3.26.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

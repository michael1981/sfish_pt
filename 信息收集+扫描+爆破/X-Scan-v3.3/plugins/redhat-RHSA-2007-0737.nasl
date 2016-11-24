
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28239);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0737: pam");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0737");
 script_set_attribute(attribute: "description", value: '
  Updated pam packages that fix two security flaws, resolve two bugs, and
  add an enhancement are now available for Red Hat Enterprise Linux 4.

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
  messages, which could possibly mislead or confuse audit log parsing tools.
  (CVE-2007-3102)

  As well, these updated packages fix the following bugs:

  * the pam_xauth module, which is used for copying the X11 authentication
  cookie, did not reset the "XAUTHORITY" variable in certain circumstances,
  causing unnecessary delays when using su command.

  * when calculating password similarity, pam_cracklib disregarded changes
  to the last character in passwords when "difok=x" (where "x" is the
  number of characters required to change) was configured in
  "/etc/pam.d/system-auth". This resulted in password changes that should
  have been successful to fail with the following error:

  BAD PASSWORD: is too similar to the old one

  This issue has been resolved in these updated packages.

  * the pam_limits module, which provides setting up system resources limits
  for user sessions, reset the nice priority of the user session to "0" if it
  was not configured otherwise in the "/etc/security/limits.conf"
  configuration file.

  These updated packages add the following enhancement:

  * a new PAM module, pam_tally2, which allows accounts to be locked after a
  maximum number of failed log in attempts.

  All users of PAM should upgrade to these updated packages, which resolve
  these issues and add this enhancement.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0737.html");
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

if ( rpm_check( reference:"pam-0.77-66.23", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pam-devel-0.77-66.23", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

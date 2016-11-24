
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25480);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0465: cdrecord");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0465");
 script_set_attribute(attribute: "description", value: '
  Updated pam packages that resolves several bugs and security flaws are now
  available for Red Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Pluggable Authentication Modules (PAM) provide a system whereby
  administrators can set up authentication policies without having to
  recompile programs that handle authentication.

  A flaw was found in the way the Linux kernel handled certain SG_IO
  commands. Console users with access to certain device files had the ability
  to damage recordable CD drives. The way pam_console handled permissions of
  these files has been modified to disallow access. This change also required
  modifications to the cdrecord application. (CVE-2004-0813)

  A flaw was found in the way pam_console set console device permissions. It
  was possible for various console devices to retain ownership of the console
  user after logging out, possibly leaking information to an unauthorized
  user. (CVE-2007-1716)

  The pam_unix module provides authentication against standard /etc/passwd
  and /etc/shadow files. The pam_stack module provides support for stacking
  PAM configuration files. Both of these modules contained small memory leaks
  which caused problems in applications calling PAM authentication repeatedly
  in the same process.

  All users of PAM should upgrade to these updated packages, which resolve
  these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:M/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0465.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0813", "CVE-2007-1716");
script_summary(english: "Check for the version of the cdrecord packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cdrecord-2.01.0.a32-0.EL3.6", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cdrecord-devel-2.01.0.a32-0.EL3.6", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mkisofs-2.01.0.a32-0.EL3.6", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pam-0.75-72", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pam-devel-0.75-72", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

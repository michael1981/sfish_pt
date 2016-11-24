
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42286);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1529: samba");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1529");
 script_set_attribute(attribute: "description", value: '
  Updated samba packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Samba is a suite of programs used by machines to share files, printers, and
  other information.

  A denial of service flaw was found in the Samba smbd daemon. An
  authenticated, remote user could send a specially-crafted response that
  would cause an smbd child process to enter an infinite loop. An
  authenticated, remote user could use this flaw to exhaust system resources
  by opening multiple CIFS sessions. (CVE-2009-2906)

  An uninitialized data access flaw was discovered in the smbd daemon when
  using the non-default "dos filemode" configuration option in "smb.conf". An
  authenticated, remote user with write access to a file could possibly use
  this flaw to change an access control list for that file, even when such
  access should have been denied. (CVE-2009-1888)

  A flaw was discovered in the way Samba handled users without a home
  directory set in the back-end password database (e.g. "/etc/passwd"). If a
  share for the home directory of such a user was created (e.g. using the
  automated "[homes]" share), any user able to access that share could see
  the whole file system, possibly bypassing intended access restrictions.
  (CVE-2009-2813)

  The mount.cifs program printed CIFS passwords as part of its debug output
  when running in verbose mode. When mount.cifs had the setuid bit set, a
  local, unprivileged user could use this flaw to disclose passwords from a
  file that would otherwise be inaccessible to that user. Note: mount.cifs
  from the samba packages distributed by Red Hat does not have the setuid bit
  set. This flaw only affected systems where the setuid bit was manually set
  by an administrator. (CVE-2009-2948)

  Users of Samba should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing this update,
  the smb service will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1529.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1888", "CVE-2009-2813", "CVE-2009-2906", "CVE-2009-2948");
script_summary(english: "Check for the version of the samba packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"samba-3.0.33-3.15.el5_4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.33-3.15.el5_4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.33-3.15.el5_4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.33-3.15.el5_4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.33-0.18.el4_8", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.33-0.18.el4_8", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.33-0.18.el4_8", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.33-0.18.el4_8", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.33-0.18.el4_8", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.33-0.18.el4_8", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.33-0.18.el4_8", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.33-0.18.el4_8", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.33-3.15.el5_4", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.33-3.15.el5_4", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.33-3.15.el5_4", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.33-3.15.el5_4", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

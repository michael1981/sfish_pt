
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42313);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1536: finch");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1536");
 script_set_attribute(attribute: "description", value: '
  Updated pidgin packages that fix a security issue are now available for Red
  Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously. The AOL
  Open System for Communication in Realtime (OSCAR) protocol is used by the
  AOL ICQ and AIM instant messaging systems.

  An invalid pointer dereference bug was found in the way the Pidgin OSCAR
  protocol implementation processed lists of contacts. A remote attacker
  could send a specially-crafted contact list to a user running Pidgin,
  causing Pidgin to crash. (CVE-2009-3615)

  These packages upgrade Pidgin to version 2.6.3. Refer to the Pidgin release
  notes for a full list of changes: http://developer.pidgin.im/wiki/ChangeLog

  All Pidgin users should upgrade to these updated packages, which correct
  this issue. Pidgin must be restarted for this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1536.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-3615");
script_summary(english: "Check for the version of the finch packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"finch-2.6.3-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"finch-devel-2.6.3-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-2.6.3-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-devel-2.6.3-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-perl-2.6.3-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-tcl-2.6.3-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-2.6.3-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-devel-2.6.3-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-perl-2.6.3-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"finch-2.6.3-2.el4", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"finch-devel-2.6.3-2.el4", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-2.6.3-2.el4", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-devel-2.6.3-2.el4", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-perl-2.6.3-2.el4", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-tcl-2.6.3-2.el4", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-2.6.3-2.el4", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-devel-2.6.3-2.el4", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-perl-2.6.3-2.el4", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"finch-2.6.3-2.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-2.6.3-2.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-perl-2.6.3-2.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpurple-tcl-2.6.3-2.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-2.6.3-2.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pidgin-perl-2.6.3-2.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

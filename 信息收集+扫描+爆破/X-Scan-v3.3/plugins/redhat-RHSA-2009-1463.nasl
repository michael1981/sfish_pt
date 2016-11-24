
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41620);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1463: newt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1463");
 script_set_attribute(attribute: "description", value: '
  Updated newt packages that fix one security issue are now available for Red
  Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Newt is a programming library for color text mode, widget-based user
  interfaces. Newt can be used to add stacked windows, entry widgets,
  checkboxes, radio buttons, labels, plain text fields, scrollbars, and so
  on, to text mode user interfaces.

  A heap-based buffer overflow flaw was found in the way newt processes
  content that is to be displayed in a text dialog box. A local attacker
  could issue a specially-crafted text dialog box display request (direct or
  via a custom application), leading to a denial of service (application
  crash) or, potentially, arbitrary code execution with the privileges of the
  user running the application using the newt library. (CVE-2009-2905)

  Users of newt should upgrade to these updated packages, which contain a
  backported patch to correct this issue. After installing the updated
  packages, all applications using the newt library must be restarted for the
  update to take effect.


');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1463.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2905");
script_summary(english: "Check for the version of the newt packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"newt-0.52.2-12.el5_4.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"newt-devel-0.52.2-12.el5_4.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"newt-0.51.5-2.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"newt-devel-0.51.5-2.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"newt-0.51.6-10.el4_8.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"newt-devel-0.51.6-10.el4_8.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"newt-0.51.6-10.el4_8.1", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"newt-devel-0.51.6-10.el4_8.1", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"newt-0.52.2-12.el5_4.1", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"newt-devel-0.52.2-12.el5_4.1", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

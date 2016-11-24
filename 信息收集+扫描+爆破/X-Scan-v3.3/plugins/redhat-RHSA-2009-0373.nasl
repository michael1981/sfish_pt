
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36032);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2009-0373: systemtap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0373");
 script_set_attribute(attribute: "description", value: '
  Updated systemtap packages that fix a security issue are now available for
  Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  SystemTap is an instrumentation infrastructure for systems running version
  2.6 of the Linux kernel. SystemTap scripts can collect system operations
  data, greatly simplifying information gathering. Collected data can then
  assist in performance measuring, functional testing, and performance and
  function problem diagnosis.

  A race condition was discovered in SystemTap that could allow users in the
  stapusr group to elevate privileges to that of members of the stapdev group
  (and hence root), bypassing directory confinement restrictions and allowing
  them to insert arbitrary SystemTap kernel modules. (CVE-2009-0784)

  Note: This issue was only exploitable if another SystemTap kernel module
  was placed in the "systemtap/" module directory for the currently running
  kernel.

  Red Hat would like to thank Erik Sjölund for reporting this issue.

  SystemTap users should upgrade to these updated packages, which contain a
  backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0373.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0784");
script_summary(english: "Check for the version of the systemtap packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"systemtap-0.7.2-3.el5_3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"systemtap-client-0.7.2-3.el5_3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"systemtap-runtime-0.7.2-3.el5_3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"systemtap-server-0.7.2-3.el5_3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"systemtap-testsuite-0.7.2-3.el5_3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"systemtap-0.6.2-2.el4_7", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"systemtap-runtime-0.6.2-2.el4_7", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"systemtap-testsuite-0.6.2-2.el4_7", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

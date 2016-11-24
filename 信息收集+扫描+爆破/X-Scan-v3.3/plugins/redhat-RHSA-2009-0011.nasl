
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35318);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0011: lcms");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0011");
 script_set_attribute(attribute: "description", value: '
  Updated lcms packages that resolve several security issues are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Little Color Management System (LittleCMS, or simply "lcms") is a
  small-footprint, speed-optimized open source color management engine.

  Multiple insufficient input validation flaws were discovered in LittleCMS.
  An attacker could use these flaws to create a specially-crafted image file
  which could cause an application using LittleCMS to crash, or, possibly,
  execute arbitrary code when opened. (CVE-2008-5316, CVE-2008-5317)

  Users of lcms should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running applications using
  lcms library must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0011.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-5316", "CVE-2008-5317");
script_summary(english: "Check for the version of the lcms packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lcms-1.15-1.2.2.el5_2.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lcms-devel-1.15-1.2.2.el5_2.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-lcms-1.15-1.2.2.el5_2.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

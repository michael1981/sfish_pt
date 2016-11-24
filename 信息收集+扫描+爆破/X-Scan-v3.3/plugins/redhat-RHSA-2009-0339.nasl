
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35970);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0339: lcms");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0339");
 script_set_attribute(attribute: "description", value: '
  Updated lcms packages that resolve several security issues are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Little Color Management System (LittleCMS, or simply "lcms") is a
  small-footprint, speed-optimized open source color management engine.

  Multiple integer overflow flaws which could lead to heap-based buffer
  overflows, as well as multiple insufficient input validation flaws, were
  found in LittleCMS. An attacker could use these flaws to create a
  specially-crafted image file which could cause an application using
  LittleCMS to crash, or, possibly, execute arbitrary code when opened by a
  victim. (CVE-2009-0723, CVE-2009-0733)

  A memory leak flaw was found in LittleCMS. An application using LittleCMS
  could use excessive amount of memory, and possibly crash after using all
  available memory, if used to open specially-crafted images. (CVE-2009-0581)

  Red Hat would like to thank Chris Evans from the Google Security Team for
  reporting these issues.

  All users of LittleCMS should install these updated packages, which upgrade
  LittleCMS to version 1.18. All running applications using the lcms library
  must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0339.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733");
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

if ( rpm_check( reference:"lcms-1.18-0.1.beta1.el5_3.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lcms-devel-1.18-0.1.beta1.el5_3.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-lcms-1.18-0.1.beta1.el5_3.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

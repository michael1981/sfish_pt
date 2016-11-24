
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40542);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1204: apr");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1204");
 script_set_attribute(attribute: "description", value: '
  Updated apr and apr-util packages that fix multiple security issues are now
  available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache Portable Runtime (APR) is a portability library used by the
  Apache HTTP Server and other projects. It aims to provide a free library
  of C data structures and routines. apr-util is a utility library used with
  APR. This library provides additional utility interfaces for APR; including
  support for XML parsing, LDAP, database interfaces, URI parsing, and more.

  Multiple integer overflow flaws, leading to heap-based buffer overflows,
  were found in the way the Apache Portable Runtime (APR) manages memory pool
  and relocatable memory allocations. An attacker could use these flaws to
  issue a specially-crafted request for memory allocation, which would lead
  to a denial of service (application crash) or, potentially, execute
  arbitrary code with the privileges of an application using the APR
  libraries. (CVE-2009-2412)

  All apr and apr-util users should upgrade to these updated packages, which
  contain backported patches to correct these issues. Applications using the
  APR libraries, such as httpd, must be restarted for this update to take
  effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1204.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2412");
script_summary(english: "Check for the version of the apr packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apr-1.2.7-11.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-devel-1.2.7-11.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-docs-1.2.7-11.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-1.2.7-7.el5_3.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-devel-1.2.7-7.el5_3.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-docs-1.2.7-7.el5_3.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-0.9.4-24.9.el4_8.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-devel-0.9.4-24.9.el4_8.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-0.9.4-22.el4_8.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-devel-0.9.4-22.el4_8.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-0.9.4-24.9.el4_8.2", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-devel-0.9.4-24.9.el4_8.2", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-0.9.4-22.el4_8.2", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-devel-0.9.4-22.el4_8.2", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-1.2.7-11.el5_3.1", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-devel-1.2.7-11.el5_3.1", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-docs-1.2.7-11.el5_3.1", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-1.2.7-7.el5_3.2", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-devel-1.2.7-7.el5_3.2", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-docs-1.2.7-7.el5_3.2", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

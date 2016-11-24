
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33496);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0562: irb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0562");
 script_set_attribute(attribute: "description", value: '
  Updated ruby packages that fix several security issues are now available
  for Red Hat Enterprise Linux 2.1 and 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ruby is an interpreted scripting language for quick and easy
  object-oriented programming.

  Multiple integer overflows leading to a heap overflow were discovered in
  the array- and string-handling code used by Ruby. An attacker could use
  these flaws to crash a Ruby application or, possibly, execute arbitrary
  code with the privileges of the Ruby application using untrusted inputs in
  array or string operations. (CVE-2008-2376, CVE-2008-2663, CVE-2008-2725,
  CVE-2008-2726)

  It was discovered that Ruby used the alloca() memory allocation function in
  the format (%) method of the String class without properly restricting
  maximum string length. An attacker could use this flaw to crash a Ruby
  application or, possibly, execute arbitrary code with the privileges of the
  Ruby application using long, untrusted strings as format strings.
  (CVE-2008-2664)

  Red Hat would like to thank Drew Yao of the Apple Product Security team for
  reporting these issues.

  A flaw was discovered in the way Ruby\'s CGI module handles certain HTTP
  requests. A remote attacker could send a specially crafted request and
  cause the Ruby CGI script to enter an infinite loop, possibly causing a
  denial of service. (CVE-2006-6303)

  Users of Ruby should upgrade to these updated packages, which contain a
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0562.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-6303", "CVE-2008-2376", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");
script_summary(english: "Check for the version of the irb packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"irb-1.6.4-6.el2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-1.6.4-6.el2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.6.4-6.el2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.6.4-6.el2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.6.4-6.el2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.6.4-6.el2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"irb-1.6.8-12.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-1.6.8-12.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.6.8-12.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.6.8-12.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.6.8-12.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-mode-1.6.8-12.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.6.8-12.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

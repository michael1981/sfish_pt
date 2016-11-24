
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34466);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0897: ruby");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0897");
 script_set_attribute(attribute: "description", value: '
  Updated ruby packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ruby is an interpreted scripting language for quick and easy
  object-oriented programming.

  The Ruby DNS resolver library, resolv.rb, used predictable transaction IDs
  and a fixed source port when sending DNS requests. A remote attacker could
  use this flaw to spoof a malicious reply to a DNS query. (CVE-2008-3905)

  Ruby\'s XML document parsing module (REXML) was prone to a denial of service
  attack via XML documents with large XML entity definitions recursion. A
  specially-crafted XML file could cause a Ruby application using the REXML
  module to use an excessive amount of CPU and memory. (CVE-2008-3790)

  An insufficient "taintness" check flaw was discovered in Ruby\'s DL module,
  which provides direct access to the C language functions. An attacker could
  use this flaw to bypass intended safe-level restrictions by calling
  external C functions with the arguments from an untrusted tainted inputs.
  (CVE-2008-3657)

  A denial of service flaw was discovered in WEBrick, Ruby\'s HTTP server
  toolkit. A remote attacker could send a specially-crafted HTTP request to a
  WEBrick server that would cause the server to use an excessive amount of
  CPU time. (CVE-2008-3656)

  A number of flaws were found in the safe-level restrictions in Ruby. It
  was possible for an attacker to create a carefully crafted malicious script
  that can allow the bypass of certain safe-level restrictions.
  (CVE-2008-3655)

  A denial of service flaw was found in Ruby\'s regular expression engine. If
  a Ruby script tried to process a large amount of data via a regular
  expression, it could cause Ruby to enter an infinite-loop and crash.
  (CVE-2008-3443)

  Users of ruby should upgrade to these updated packages, which contain
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0897.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1145", "CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");
script_summary(english: "Check for the version of the ruby packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ruby-1.8.5-5.el5_2.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.5-5.el5_2.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.8.5-5.el5_2.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-irb-1.8.5-5.el5_2.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.8.5-5.el5_2.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-mode-1.8.5-5.el5_2.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-rdoc-1.8.5-5.el5_2.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-ri-1.8.5-5.el5_2.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.8.5-5.el5_2.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"irb-1.8.1-7.el4_7.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-1.8.1-7.el4_7.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.1-7.el4_7.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.8.1-7.el4_7.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.8.1-7.el4_7.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-mode-1.8.1-7.el4_7.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.8.1-7.el4_7.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34465);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0896: irb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0896");
 script_set_attribute(attribute: "description", value: '
  Updated ruby packages that fix several security issues are now available
  for Red Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ruby is an interpreted scripting language for quick and easy
  object-oriented programming.

  The Ruby DNS resolver library, resolv.rb, used predictable transaction IDs
  and a fixed source port when sending DNS requests. A remote attacker could
  use this flaw to spoof a malicious reply to a DNS query. (CVE-2008-3905)

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
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0896.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3905");
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

if ( rpm_check( reference:"irb-1.6.8-13.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-1.6.8-13.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.6.8-13.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.6.8-13.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.6.8-13.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-mode-1.6.8-13.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.6.8-13.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

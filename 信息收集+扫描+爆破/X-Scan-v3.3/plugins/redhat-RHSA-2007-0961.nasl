
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28201);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0961: irb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0961");
 script_set_attribute(attribute: "description", value: '
  Updated ruby packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ruby is an interpreted scripting language for object-oriented programming.

  A flaw was discovered in the way Ruby\'s CGI module handles certain HTTP
  requests. If a remote attacker sends a specially crafted request, it is
  possible to cause the ruby CGI script to enter an infinite loop, possibly
  causing a denial of service. (CVE-2006-6303)

  An SSL certificate validation flaw was discovered in several Ruby Net
  modules. The libraries were not checking the requested host name against
  the common name (CN) in the SSL server certificate, possibly allowing a man
  in the middle attack. (CVE-2007-5162, CVE-2007-5770)

  Users of Ruby should upgrade to these updated packages, which contain
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0961.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-6303", "CVE-2007-5162", "CVE-2007-5770");
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

if ( rpm_check( reference:"irb-1.8.1-7.EL4.8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-1.8.1-7.EL4.8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.1-7.EL4.8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.8.1-7.EL4.8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.8.1-7.EL4.8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-mode-1.8.1-7.EL4.8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.8.1-7.EL4.8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

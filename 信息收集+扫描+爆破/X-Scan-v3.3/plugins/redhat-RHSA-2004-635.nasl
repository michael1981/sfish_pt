
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15945);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2004-635: irb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-635");
 script_set_attribute(attribute: "description", value: '
  An updated ruby package that fixes a denial of service issue for the CGI
  instance is now available.

  [Updated 17 Jan 2005]
  Errata has been updated to include 32-bit libraries on 64-bit
  architectures.

  Ruby is an interpreted scripting language for object-oriented programming.

  A flaw was dicovered in the CGI module of Ruby. If empty data is sent by
  the POST method to the CGI script which requires MIME type
  multipart/form-data, it can get stuck in a loop. A remote attacker could
  trigger this flaw and cause a denial of service. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0983 to this issue.

  Users are advised to upgrade to this erratum package, which contains a
  backported patch to cgi.rb.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-635.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0983");
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

if ( rpm_check( reference:"irb-1.6.4-2.AS21.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-1.6.4-2.AS21.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.6.4-2.AS21.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.6.4-2.AS21.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.6.4-2.AS21.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.6.4-2.AS21.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"irb-1.6.8-9.EL3.3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-1.6.8-9.EL3.3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.6.8-9.EL3.3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.6.8-9.EL3.3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.6.8-9.EL3.3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-mode-1.6.8-9.EL3.3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.6.8-9.EL3.3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

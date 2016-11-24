
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12450);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-015: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-015");
 script_set_attribute(attribute: "description", value: '
  Updated httpd packages that fix two minor security issues in the Apache Web
  server are now available for Red Hat Enterprise Linux 3.

  The Apache HTTP Server is a powerful, full-featured, efficient, and
  freely-available Web server.

  An issue in the handling of regular expressions from configuration files
  was discovered in releases of the Apache HTTP Server version 2.0 prior to
  2.0.48. To exploit this issue an attacker would need to have the ability
  to write to Apache configuration files such as .htaccess or httpd.conf. A
  carefully-crafted configuration file can cause an exploitable buffer
  overflow and would allow the attacker to execute arbitrary code in the
  context of the server (in default configurations as the \'apache\' user).
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2003-0542 to this issue.

  Users of the Apache HTTP Server should upgrade to these erratum packages,
  which contain backported patches correcting these issues, and are applied
  to Apache version 2.0.46. This update also includes fixes for a number of
  minor bugs found in this version of the Apache HTTP Server.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-015.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0542");
script_summary(english: "Check for the version of the httpd packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"httpd-2.0.46-26.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-26.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-26.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

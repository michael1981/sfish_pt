
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12473);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-084: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-084");
 script_set_attribute(attribute: "description", value: '
  Updated httpd packages are now available that fix a denial of service
  vulnerability in mod_ssl and include various other bug fixes.

  The Apache HTTP server is a powerful, full-featured, efficient, and
  freely-available Web server.

  A memory leak in mod_ssl in the Apache HTTP Server prior to version 2.0.49
  allows a remote denial of service attack against an SSL-enabled server. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-0113 to this issue.

  This update also includes various bug fixes, including:

  - improvements to the mod_expires, mod_dav, mod_ssl and mod_proxy modules

  - a fix for a bug causing core dumps during configuration parsing on the
  IA64 platform

  - an updated version of mod_include fixing several edge cases in the SSI
  parser

  Additionally, the mod_logio module is now included.

  Users of the Apache HTTP server should upgrade to these updated packages,
  which contain backported patches that address these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-084.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0113");
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

if ( rpm_check( reference:"httpd-2.0.46-32.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-32.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-32.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

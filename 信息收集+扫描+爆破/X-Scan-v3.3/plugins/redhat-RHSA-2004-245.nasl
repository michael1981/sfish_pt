
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12506);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2004-245: apache");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-245");
 script_set_attribute(attribute: "description", value: '
  Updated httpd and mod_ssl packages that fix minor security issues in
  the Apache Web server are now available for Red Hat Enterprise Linux 2.1.

  The Apache HTTP Server is a powerful, full-featured, efficient, and
  freely-available Web server.

  A buffer overflow was found in the Apache proxy module, mod_proxy, which
  can be triggered by receiving an invalid Content-Length header. In order
  to exploit this issue, an attacker would need an Apache installation
  that was configured as a proxy to connect to a malicious site. This would
  cause the Apache child processing the request to crash. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0492 to this issue.

  On Red Hat Enterprise Linux platforms Red Hat believes this issue cannot
  lead to remote code execution. This issue also does not represent a Denial
  of Service attack as requests will continue to be handled by other Apache
  child processes.

  A stack buffer overflow was discovered in mod_ssl which can be triggered if
  using the FakeBasicAuth option. If mod_ssl is sent a client certificate
  with a subject DN field longer than 6000 characters, a stack overflow can
  occur if FakeBasicAuth has been enabled. In order to exploit this issue
  the carefully crafted malicious certificate would have to be signed by a
  Certificate Authority which mod_ssl is configured to trust. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0488 to this issue.

  This update also fixes a DNS handling bug in mod_proxy.

  The mod_auth_digest module is now included in the Apache package and should
  be used instead of mod_digest for sites requiring Digest authentication.

  Red Hat Enterprise Linux 2.1 users of the Apache HTTP Server should upgrade
  to these erratum packages, which contains Apache version 1.3.27 with
  backported patches correcting these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-245.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0488", "CVE-2004-0492");
script_summary(english: "Check for the version of the apache packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apache-1.3.27-8.ent", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.27-8.ent", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.27-8.ent", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.12-4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

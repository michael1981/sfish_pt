
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12636);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2004-342: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-342");
 script_set_attribute(attribute: "description", value: '
  Updated httpd packages that fix a buffer overflow in mod_ssl and a remotely
  triggerable memory leak are now available.

  The Apache HTTP server is a powerful, full-featured, efficient, and
  freely-available Web server.

  A stack buffer overflow was discovered in mod_ssl that could be triggered
  if using the FakeBasicAuth option. If mod_ssl was sent a client certificate
  with a subject DN field longer than 6000 characters, a stack overflow
  occured if FakeBasicAuth had been enabled. In order to exploit this issue
  the carefully crafted malicious certificate would have had to be signed by
  a Certificate Authority which mod_ssl is configured to trust. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0488 to this issue.

  A remotely triggered memory leak in the Apache HTTP Server earlier than
  version 2.0.50 was also discovered. This allowed a remote attacker to
  perform a denial of service attack against the server by forcing it to
  consume large amounts of memory. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-0493 to this issue.

  Users of the Apache HTTP server should upgrade to these updated packages,
  which contain backported patches that address these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-342.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0488", "CVE-2004-0493");
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

if ( rpm_check( reference:"httpd-2.0.46-32.ent.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-32.ent.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-32.ent.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

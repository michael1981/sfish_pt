
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14698);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-408: mod_ssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-408");
 script_set_attribute(attribute: "description", value: '
  An updated mod_ssl package for Apache that fixes a format string
  vulnerability is now available.

  The mod_ssl module provides strong cryptography for the Apache Web
  server via the Secure Sockets Layer (SSL) and Transport Layer Security
  (TLS) protocols.

  A format string issue was discovered in mod_ssl for Apache 1.3 which can be
  triggered if mod_ssl is configured to allow a client to proxy to remote SSL
  sites. In order to exploit this issue, a user who is authorized to use
  Apache as a proxy would have to attempt to connect to a carefully crafted
  hostname via SSL. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0700 to this issue.

  Users of mod_ssl should upgrade to this updated package, which contains a
  backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-408.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0700");
script_summary(english: "Check for the version of the mod_ssl packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mod_ssl-2.8.12-6", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12504);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-242: squid");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-242");
 script_set_attribute(attribute: "description", value: '
  An updated squid package that fixes a security vulnerability in
  the NTLM authentication helper is now available.

  Squid is a full-featured Web proxy cache.

  A buffer overflow was found within the NTLM authentication helper
  routine. If Squid is configured to use the NTLM authentication helper,
  a remote attacker could potentially execute arbitrary code by sending a
  lengthy password. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0541 to this issue.

  Note: The NTLM authentication helper is not enabled by default in Red Hat
  Enterprise Linux 3. Red Hat Enterprise Linux 2.1 is not vulnerable to this
  issue as it shipped with a version of Squid which did not contain the
  helper.

  Users of Squid should update to this errata package which contains a
  backported patch that is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-242.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0541");
script_summary(english: "Check for the version of the squid packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"squid-2.5.STABLE3-6.3E", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14215);
 script_version ("$Revision: 1.11 $");
 script_name(english: "RHSA-2004-378: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-378");
 script_set_attribute(attribute: "description", value: '
  Updated Ethereal packages that fix various security vulnerabilities are now
  available.

  Ethereal is a program for monitoring network traffic.

  The SNMP dissector in Ethereal releases 0.8.15 through 0.10.4 contained a
  memory read flaw. On a system where Ethereal is running, a remote
  attacker could send malicious packets that could cause Ethereal to crash or
  possibly execute arbitrary code. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-0635 to this issue.

  The SMB dissector in Ethereal releases 0.9.15 through 0.10.4 contained a
  null pointer flaw. On a system where Ethereal is running, a remote
  attacker could send malicious packets that could cause Ethereal to crash.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2004-0634 to this issue.

  The iSNS dissector in Ethereal releases 0.10.3 through 0.10.4 contained an
  integer overflow flaw. On a system where Ethereal is running, a remote
  attacker could send malicious packets that could cause Ethereal to crash or
  possibly execute arbitrary code. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-0633 to this issue.

  Users of Ethereal should upgrade to these updated packages, which contain
  a version that is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-378.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0633", "CVE-2004-0634", "CVE-2004-0635");
script_summary(english: "Check for the version of the ethereal packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ethereal-0.10.5-0.AS21.2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.5-0.AS21.2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.5-0.30E.2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.5-0.30E.2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

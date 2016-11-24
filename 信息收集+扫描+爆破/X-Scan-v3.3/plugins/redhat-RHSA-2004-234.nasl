
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12501);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-234: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-234");
 script_set_attribute(attribute: "description", value: '
  Updated Ethereal packages that fix various security vulnerabilities are now
  available.

  Ethereal is a program for monitoring network traffic.

  The MMSE dissector in Ethereal releases 0.10.1 through 0.10.3 contained a
  buffer overflow flaw. On a system where Ethereal is running, a remote
  attacker could send malicious packets that could cause Ethereal to crash or
  execute arbitrary code. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0507 to this issue.

  In addition, other flaws in Ethereal prior to 0.10.4 were found that could
  cause it to crash in response to carefully crafted SIP (CAN-2004-0504), AIM
  (CAN-2004-0505), or SPNEGO (CAN-2004-0506) packets.

  Users of Ethereal should upgrade to these updated packages, which contain
  backported security patches that correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-234.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0504", "CVE-2004-0505", "CVE-2004-0506", "CVE-2004-0507");
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

if ( rpm_check( reference:"ethereal-0.10.3-0.AS21.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.3-0.AS21.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.3-0.30E.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.3-0.30E.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

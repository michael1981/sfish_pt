
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12448);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2004-008: arpwatch");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-008");
 script_set_attribute(attribute: "description", value: '
  Updated tcpdump, libpcap, and arpwatch packages fix vulnerabilities in
  ISAKMP and RADIUS parsing.

  [Updated 15 Jan 2004]
  Updated the text description to better describe the vulnerabilities found
  by Jonathan Heusser and give them CVE names.

  Tcpdump is a command-line tool for monitoring network traffic.

  George Bakos discovered flaws in the ISAKMP decoding routines of tcpdump
  versions prior to 3.8.1. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2003-0989 to this issue.

  Jonathan Heusser discovered an additional flaw in the ISAKMP decoding
  routines for tcpdump 3.8.1 and earlier. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-0057 to
  this issue.

  Jonathan Heusser discovered a flaw in the print_attr_string function in the
  RADIUS decoding routines for tcpdump 3.8.1 and earlier. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0055 to this issue.

  Remote attackers could potentially exploit these issues by sending
  carefully-crafted packets to a victim. If the victim uses tcpdump, these
  pakets could result in a denial of service, or possibly execute arbitrary
  code as the \'pcap\' user.

  Users of tcpdump are advised to upgrade to these erratum packages, which
  contain backported security patches and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-008.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0989", "CVE-2004-0055", "CVE-2004-0057");
script_summary(english: "Check for the version of the arpwatch packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"arpwatch-2.1a11-12.2.1AS.5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.6.2-12.2.1AS.5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-12.2.1AS.5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.7.2-7.E3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-7.E3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

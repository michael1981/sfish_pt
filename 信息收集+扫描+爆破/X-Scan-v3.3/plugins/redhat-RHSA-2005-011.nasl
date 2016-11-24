
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16295);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-011: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-011");
 script_set_attribute(attribute: "description", value: '
  Updated Ethereal packages that fix various security vulnerabilities are now
  available.

  Ethereal is a program for monitoring network traffic.

  A number of security flaws have been discovered in Ethereal. On a system
  where Ethereal is running, a remote attacker could send malicious packets
  to trigger these flaws.

  A flaw in the DICOM dissector could cause a crash. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2004-1139 to this issue.

  A invalid RTP timestamp could hang Ethereal and create a large temporary
  file, possibly filling available disk space. (CAN-2004-1140)

  The HTTP dissector could access previously-freed memory, causing a crash.
  (CAN-2004-1141)

  An improperly formatted SMB packet could make Ethereal hang, maximizing CPU
  utilization. (CAN-2004-1142)

  The COPS dissector could go into an infinite loop. (CAN-2005-0006)

  The DLSw dissector could cause an assertion, making Ethereal exit
  prematurely. (CAN-2005-0007)

  The DNP dissector could cause memory corruption. (CAN-2005-0008)

  The Gnutella dissector could cause an assertion, making Ethereal exit
  prematurely. (CAN-2005-0009)

  The MMSE dissector could free static memory, causing a crash. (CAN-2005-0010)

  The X11 protocol dissector is vulnerable to a string buffer overflow.
  (CAN-2005-0084)

  Users of Ethereal should upgrade to these updated packages which contain
  version 0.10.9 that is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-011.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1139", "CVE-2004-1140", "CVE-2004-1141", "CVE-2004-1142", "CVE-2005-0006", "CVE-2005-0007", "CVE-2005-0008", "CVE-2005-0009", "CVE-2005-0010", "CVE-2005-0084");
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

if ( rpm_check( reference:"ethereal-0.10.9-1.AS21.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.9-1.AS21.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.9-1.EL3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.9-1.EL3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22243);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0602: wireshark");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0602");
 script_set_attribute(attribute: "description", value: '
  New Wireshark packages that fix various security vulnerabilities in
  Ethereal are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ethereal is a program for monitoring network traffic.

  In May 2006, Ethereal changed its name to Wireshark. This update
  deprecates the Ethereal packages in Red Hat Enterprise Linux 2.1, 3, and 4
  in favor of the supported Wireshark packages.

  Several denial of service bugs were found in Ethereal\'s protocol
  dissectors. It was possible for Ethereal to crash or stop responding if it
  read a malformed packet off the network. (CVE-2006-3627, CVE-2006-3629,
  CVE-2006-3631)

  Several buffer overflow bugs were found in Ethereal\'s ANSI MAP, NCP NMAS,
  and NDPStelnet dissectors. It was possible for Ethereal to crash or execute
  arbitrary code if it read a malformed packet off the network.
  (CVE-2006-3630, CVE-2006-3632)

  Several format string bugs were found in Ethereal\'s Checkpoint FW-1, MQ,
  XML, and NTP dissectors. It was possible for Ethereal to crash or execute
  arbitrary code if it read a malformed packet off the network. (CVE-2006-3628)

  Users of Ethereal should upgrade to these updated packages containing
  Wireshark version 0.99.2, which is not vulnerable to these issues


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0602.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-3627", "CVE-2006-3628", "CVE-2006-3629", "CVE-2006-3630", "CVE-2006-3631", "CVE-2006-3632");
script_summary(english: "Check for the version of the wireshark packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"wireshark-0.99.2-AS21.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.2-AS21.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.2-EL3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.2-EL3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.2-EL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.2-EL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

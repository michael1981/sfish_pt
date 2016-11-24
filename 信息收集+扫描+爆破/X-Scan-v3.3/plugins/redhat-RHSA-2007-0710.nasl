
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27833);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0710: wireshark");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0710");
 script_set_attribute(attribute: "description", value: '
  New Wireshark packages that fix various security vulnerabilities are now
  available for Red Hat Enterprise Linux 5. Wireshark was previously known
  as Ethereal.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Wireshark is a program for monitoring network traffic.

  Several denial of service bugs were found in Wireshark\'s HTTP, iSeries, DCP
  ETSI, SSL, MMS, DHCP and BOOTP protocol dissectors. It was possible for
  Wireshark to crash or stop responding if it read a malformed packet off the
  network. (CVE-2007-3389, CVE-2007-3390, CVE-2007-3391, CVE-2007-3392,
  CVE-2007-3393)

  Users of Wireshark and Ethereal should upgrade to these updated packages,
  containing Wireshark version 0.99.6, which is not vulnerable to these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0710.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3389", "CVE-2007-3390", "CVE-2007-3391", "CVE-2007-3392", "CVE-2007-3393");
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

if ( rpm_check( reference:"wireshark-0.99.6-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.6-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

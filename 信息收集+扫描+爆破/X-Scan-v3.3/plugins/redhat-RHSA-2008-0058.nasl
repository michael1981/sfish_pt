
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(30034);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0058: libsmi");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0058");
 script_set_attribute(attribute: "description", value: '
  Updated wireshark packages that fix several security issues are now
  available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Wireshark is a program for monitoring network traffic. Wireshark was
  previously known as Ethereal.

  Several flaws were found in Wireshark. Wireshark could crash or possibly
  execute arbitrary code as the user running Wireshark if it read a malformed
  packet off the network. (CVE-2007-6112, CVE-2007-6114, CVE-2007-6115,
  CVE-2007-6117)

  Several denial of service bugs were found in Wireshark. Wireshark could
  crash or stop responding if it read a malformed packet off the network.
  (CVE-2007-6111, CVE-2007-6113, CVE-2007-6116, CVE-2007-6118, CVE-2007-6119,
  CVE-2007-6120, CVE-2007-6121, CVE-2007-6438, CVE-2007-6439, CVE-2007-6441,
  CVE-2007-6450, CVE-2007-6451)

  As well, Wireshark switched from using net-snmp to libsmi, which is
  included in this errata.

  Users of wireshark should upgrade to these updated packages, which contain
  Wireshark version 0.99.7, and resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0058.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-6111", "CVE-2007-6112", "CVE-2007-6113", "CVE-2007-6114", "CVE-2007-6115", "CVE-2007-6116", "CVE-2007-6117", "CVE-2007-6118", "CVE-2007-6119", "CVE-2007-6120", "CVE-2007-6121", "CVE-2007-6438", "CVE-2007-6439", "CVE-2007-6441", "CVE-2007-6450", "CVE-2007-6451");
script_summary(english: "Check for the version of the libsmi packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libsmi-0.4.5-2.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsmi-devel-0.4.5-2.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.7-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.7-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsmi-0.4.5-2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsmi-devel-0.4.5-2.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.7-1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.7-1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

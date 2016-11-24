
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34328);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0890: wireshark");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0890");
 script_set_attribute(attribute: "description", value: '
  Updated wireshark packages that fix several security issues are now
  available for Red Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Wireshark is a program for monitoring network traffic. Wireshark was
  previously known as Ethereal.

  Multiple buffer overflow flaws were found in Wireshark. If Wireshark read
  a malformed packet off a network, it could crash or, possibly, execute
  arbitrary code as the user running Wireshark. (CVE-2008-3146)

  Several denial of service flaws were found in Wireshark. Wireshark could
  crash or stop responding if it read a malformed packet off a network, or
  opened a malformed dump file. (CVE-2008-1070, CVE-2008-1071, CVE-2008-1072,
  CVE-2008-1561, CVE-2008-1562, CVE-2008-1563, CVE-2008-3137, CVE-2008-3138,
  CVE-2008-3141, CVE-2008-3145, CVE-2008-3932, CVE-2008-3933, CVE-2008-3934)

  Additionally, this update changes the default Pluggable Authentication
  Modules (PAM) configuration to always prompt for the root password before
  each start of Wireshark. This avoids unintentionally running Wireshark with
  root privileges.

  Users of wireshark should upgrade to these updated packages, which contain
  Wireshark version 1.0.3, and resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0890.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1070", "CVE-2008-1071", "CVE-2008-1072", "CVE-2008-1561", "CVE-2008-1562", "CVE-2008-1563", "CVE-2008-3137", "CVE-2008-3138", "CVE-2008-3141", "CVE-2008-3145", "CVE-2008-3146", "CVE-2008-3932", "CVE-2008-3933", "CVE-2008-3934");
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

if ( rpm_check( reference:"wireshark-1.0.3-4.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-1.0.3-4.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-1.0.3-EL3.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-1.0.3-EL3.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-1.0.3-3.el4_7", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-1.0.3-3.el4_7", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

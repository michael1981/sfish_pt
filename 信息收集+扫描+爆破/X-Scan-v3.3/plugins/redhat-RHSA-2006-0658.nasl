
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22344);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0658: wireshark");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0658");
 script_set_attribute(attribute: "description", value: '
  New Wireshark packages that fix various security vulnerabilities are now
  available. Wireshark was previously known as Ethereal.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Wireshark is a program for monitoring network traffic.

  Bugs were found in Wireshark\'s SCSI and SSCOP protocol dissectors. Ethereal
  could crash or stop responding if it read a malformed packet off the
  network. (CVE-2006-4330, CVE-2006-4333)

  An off-by-one bug was found in the IPsec ESP decryption preference parser.
  Ethereal could crash or stop responding if it read a malformed packet off
  the network. (CVE-2006-4331)

  Users of Wireshark or Ethereal should upgrade to these updated packages
  containing Wireshark version 0.99.3, which is not vulnerable to these
  issues. These packages also fix a bug in the PAM configuration of the
  Wireshark packages which prevented non-root users starting a capture.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0658.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4330", "CVE-2006-4331", "CVE-2006-4333");
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

if ( rpm_check( reference:"wireshark-0.99.3-AS21.4", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.3-AS21.4", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.3-EL3.2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.3-EL3.2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.3-EL4.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.3-EL4.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

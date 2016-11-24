
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25238);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0065: bluez");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0065");
 script_set_attribute(attribute: "description", value: '
  Updated bluez-utils packages that fix a security flaw are now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The bluez-utils package contains Bluetooth daemons and utilities.

  A flaw was found in the Bluetooth HID daemon (hidd). A remote attacker
  would have been able to inject keyboard and mouse events via a Bluetooth
  connection without any authorization. (CVE-2006-6899)

  Note that Red Hat Enterprise Linux does not come with the Bluetooth HID
  daemon enabled by default.

  Users of bluez-utils are advised to upgrade to these updated packages,
  which
  contains a backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0065.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-6899");
script_summary(english: "Check for the version of the bluez packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"bluez-utils-2.10-2.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bluez-utils-cups-2.10-2.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

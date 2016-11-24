
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35317);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0008: dbus");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0008");
 script_set_attribute(attribute: "description", value: '
  Updated dbus packages that fix a security issue are now available for Red
  Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  D-Bus is a system for sending messages between applications. It is used for
  the system-wide message bus service and as a per-user-login-session
  messaging facility.

  A denial-of-service flaw was discovered in the system for sending messages
  between applications. A local user could send a message with a malformed
  signature to the bus causing the bus (and, consequently, any process using
  libdbus to receive messages) to abort. (CVE-2008-3834)

  All users are advised to upgrade to these updated dbus packages, which
  contain backported patch which resolve this issue. For the update to take
  effect, all running instances of dbus-daemon and all running applications
  using libdbus library must be restarted, or the system rebooted.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0008.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-3834");
script_summary(english: "Check for the version of the dbus packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dbus-1.0.0-7.el5_2.1", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dbus-devel-1.0.0-7.el5_2.1", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dbus-x11-1.0.0-7.el5_2.1", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31308);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0159: dbus");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0159");
 script_set_attribute(attribute: "description", value: '
  Updated dbus packages that fix an issue with circumventing the security
  policy are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  D-Bus is a system for sending messages between applications. It is used
  both for the system-wide message bus service, and as a
  per-user-login-session messaging facility.

  Havoc Pennington discovered a flaw in the way the dbus-daemon applies its
  security policy. A user with the ability to connect to the dbus-daemon may
  be able to execute certain method calls they should normally not have
  permission to access. (CVE-2008-0595)

  Red Hat does not ship any applications in Red Hat Enterprise Linux 5 that
  would allow a user to leverage this flaw to elevate their privileges.

  This flaw does not affect the version of D-Bus shipped in Red Hat
  Enterprise Linux 4.

  All users are advised to upgrade to these updated dbus packages, which
  contain a backported patch and are not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0159.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-0595");
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

if ( rpm_check( reference:"dbus-1.0.0-6.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dbus-devel-1.0.0-6.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dbus-x11-1.0.0-6.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18557);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-524: freeradius");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-524");
 script_set_attribute(attribute: "description", value: '
  Updated freeradius packages that fix a buffer overflow and possible SQL
  injection attacks in the sql module are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  FreeRADIUS is a high-performance and highly configurable free RADIUS server
  designed to allow centralized authentication and authorization for a network.

  A buffer overflow bug was found in the way FreeRADIUS escapes data in an
  SQL query. An attacker may be able to crash FreeRADIUS if they cause
  FreeRADIUS to escape a string containing three or less characters. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2005-1454 to this issue.

  Additionally a bug was found in the way FreeRADIUS escapes SQL data. It is
  possible that an authenticated user could execute arbitrary SQL queries by
  sending a specially crafted request to FreeRADIUS. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-1455 to this issue.

  Users of FreeRADIUS should update to these erratum packages, which contain
  backported patches and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-524.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1454", "CVE-2005-1455");
script_summary(english: "Check for the version of the freeradius packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"freeradius-1.0.1-1.1.RHEL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freeradius-1.0.1-3.RHEL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freeradius-mysql-1.0.1-3.RHEL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freeradius-postgresql-1.0.1-3.RHEL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freeradius-unixODBC-1.0.1-3.RHEL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

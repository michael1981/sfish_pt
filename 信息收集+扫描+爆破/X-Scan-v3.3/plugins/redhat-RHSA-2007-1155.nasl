
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29737);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-1155: mysql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1155");
 script_set_attribute(attribute: "description", value: '
  Updated mysql packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
  client/server implementation consisting of a server daemon (mysqld), and
  many different client programs and libraries.

  A flaw was found in a way MySQL handled symbolic links when database tables
  were created with explicit "DATA" and "INDEX DIRECTORY" options. An
  authenticated user could create a table that would overwrite tables in
  other databases, causing destruction of data or allowing the user to
  elevate privileges. (CVE-2007-5969)

  A flaw was found in a way MySQL\'s InnoDB engine handled spatial indexes. An
  authenticated user could create a table with spatial indexes, which are not
  supported by the InnoDB engine, that would cause the mysql daemon to crash
  when used. This issue only causes a temporary denial of service, as the
  mysql daemon will be automatically restarted after the crash.
  (CVE-2007-5925)

  All mysql users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1155.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5925", "CVE-2007-5969");
script_summary(english: "Check for the version of the mysql packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mysql-5.0.22-2.2.el5_1.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-5.0.22-2.2.el5_1.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-5.0.22-2.2.el5_1.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-server-5.0.22-2.2.el5_1.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-test-5.0.22-2.2.el5_1.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-4.1.20-3.RHEL4.1.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-4.1.20-3.RHEL4.1.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-4.1.20-3.RHEL4.1.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-server-4.1.20-3.RHEL4.1.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

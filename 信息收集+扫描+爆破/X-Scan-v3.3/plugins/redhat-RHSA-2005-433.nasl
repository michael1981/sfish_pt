
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18408);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-433: rh");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-433");
 script_set_attribute(attribute: "description", value: '
  Updated postgresql packages that fix several security vulnerabilities and
  risks of data loss are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  PostgreSQL is an advanced Object-Relational database management system
  (DBMS) that supports almost all SQL constructs (including
  transactions, subselects and user-defined types and functions).

  The PostgreSQL community discovered two distinct errors in initial system
  catalog entries that could allow authorized database users to crash the
  database and possibly escalate their privileges. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
  names CAN-2005-1409 and CAN-2005-1410 to these issues.

  Although installing this update will protect new (freshly initdb\'d)
  database installations from these errors, administrators MUST TAKE MANUAL
  ACTION to repair the errors in pre-existing databases. The appropriate
  procedures are explained at
  http://www.postgresql.org/docs/8.0/static/release-7-4-8.html
  for Red Hat Enterprise Linux 4 users, or
  http://www.postgresql.org/docs/8.0/static/release-7-3-10.html
  for Red Hat Enterprise Linux 3 users.

  This update corrects several problems that might occur while trying to
  upgrade a Red Hat Enterprise Linux 3 installation (containing rh-postgresql
  packages) to Red Hat Enterprise Linux 4 (containing postgresql packages).
  These updated packages correctly supersede the rh-postgresql packages.

  The original release of Red Hat Enterprise Linux 4 failed to initialize the
  database correctly if started for the first time with SELinux in
  enforcement mode. This update corrects that problem.

  If you already have a nonfunctional database in place, shut down the
  postgresql service if running, install this update, then do "sudo rm -rf
  /var/lib/pgsql/data" before restarting the postgresql service.

  This update also solves the problem that the PostgreSQL server might fail
  to restart after a system reboot, due to a stale lockfile.

  This update also corrects a problem with wrong error messages in libpq,
  the postgresql client library. The library would formerly report kernel
  error messages incorrectly when the locale setting was not C.

  This update also includes fixes for several other errors, including two
  race conditions that could result in apparent data inconsistency or actual
  data loss.

  All users of PostgreSQL are advised to upgrade to these updated packages
  and to apply the recommended manual corrections to existing databases.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-433.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1409", "CVE-2005-1410");
script_summary(english: "Check for the version of the rh packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"rh-postgresql-7.3.10-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-contrib-7.3.10-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-devel-7.3.10-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-docs-7.3.10-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-jdbc-7.3.10-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-libs-7.3.10-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-pl-7.3.10-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-python-7.3.10-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-server-7.3.10-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-tcl-7.3.10-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-test-7.3.10-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-7.4.8-1.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.4.8-1.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.4.8-1.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.4.8-1.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-jdbc-7.4.8-1.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.4.8-1.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-7.4.8-1.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-python-7.4.8-1.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.4.8-1.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-tcl-7.4.8-1.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-7.4.8-1.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");


#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33585);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0768: mysql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0768");
 script_set_attribute(attribute: "description", value: '
  Updated mysql packages that fix various security issues, several bugs, and
  add an enhancement are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
  client/server implementation consisting of a server daemon (mysqld), and
  many different client programs and libraries.

  MySQL did not correctly check directories used as arguments for the DATA
  DIRECTORY and INDEX DIRECTORY directives. Using this flaw, an authenticated
  attacker could elevate their access privileges to tables created by other
  database users. Note: this attack does not work on existing tables. An
  attacker can only elevate their access to another user\'s tables as the
  tables are created. As well, the names of these created tables need to be
  predicted correctly for this attack to succeed. (CVE-2008-2079)

  MySQL did not require the "DROP" privilege for "RENAME TABLE" statements.
  An authenticated user could use this flaw to rename arbitrary tables.
  (CVE-2007-2691)

  MySQL allowed an authenticated user to access a table through a previously
  created MERGE table, even after the user\'s privileges were revoked from the
  original table, which might violate intended security policy. This is
  addressed by allowing the MERGE storage engine to be disabled, which can be
  done by running mysqld with the "--skip-merge" option. (CVE-2006-4031)

  A flaw in MySQL allowed an authenticated user to cause the MySQL daemon to
  crash via crafted SQL queries. This only caused a temporary denial of
  service, as the MySQL daemon is automatically restarted after the crash.
  (CVE-2006-3469)

  As well, these updated packages fix the following bugs:

  * in the previous mysql packages, if a column name was referenced more
  than once in an "ORDER BY" section of a query, a segmentation fault
  occurred.

  * when MySQL failed to start, the init script returned a successful (0)
  exit code. When using the Red Hat Cluster Suite, this may have caused
  cluster services to report a successful start, even when MySQL failed to
  start. In these updated packages, the init script returns the correct exit
  codes, which resolves this issue.

  * it was possible to use the mysqld_safe command to specify invalid port
  numbers (higher than 65536), causing invalid ports to be created, and, in
  some cases, a "port number definition: unsigned short" error. In these
  updated packages, when an invalid port number is specified, the default
  port number is used.

  * when setting "myisam_repair_threads > 1", any repair set the index
  cardinality to "1", regardless of the table size.

  * the MySQL init script no longer runs "chmod -R" on the entire database
  directory tree during every startup.

  * when running "mysqldump" with the MySQL 4.0 compatibility mode option,
  "--compatible=mysql40", mysqldump created dumps that omitted the
  "auto_increment" field.

  As well, the MySQL init script now uses more reliable methods for
  determining parameters, such as the data directory location.

  Note: these updated packages upgrade MySQL to version 4.1.22. For a full
  list of bug fixes and enhancements, refer to the MySQL release notes:
  http://dev.mysql.com/doc/refman/4.1/en/news-4-1-22.html

  All mysql users are advised to upgrade to these updated packages, which
  resolve these issues and add this enhancement.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0768.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-3469", "CVE-2006-4031", "CVE-2007-2691", "CVE-2008-2079");
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

if ( rpm_check( reference:"mysql-4.1.22-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-4.1.22-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-4.1.22-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-server-4.1.22-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

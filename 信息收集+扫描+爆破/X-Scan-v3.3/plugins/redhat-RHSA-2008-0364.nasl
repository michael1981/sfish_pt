
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32425);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0364: mysql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0364");
 script_set_attribute(attribute: "description", value: '
  Updated mysql packages that fix various security issues and several bugs
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
  client/server implementation consisting of a server daemon (mysqld), and
  many different client programs and libraries.

  MySQL did not require privileges such as "SELECT" for the source table in a
  "CREATE TABLE LIKE" statement. An authenticated user could obtain sensitive
  information, such as the table structure. (CVE-2007-3781)

  A flaw was discovered in MySQL that allowed an authenticated user to gain
  update privileges for a table in another database, via a view that refers
  to the external table. (CVE-2007-3782)

  MySQL did not require the "DROP" privilege for "RENAME TABLE" statements.
  An authenticated user could use this flaw to rename arbitrary tables.
  (CVE-2007-2691)

  A flaw was discovered in the mysql_change_db function when returning from
  SQL SECURITY INVOKER stored routines. An authenticated user could use this
  flaw to gain database privileges. (CVE-2007-2692)

  MySQL allowed an authenticated user to bypass logging mechanisms via SQL
  queries that contain the NULL character, which were not properly handled by
  the mysql_real_query function. (CVE-2006-0903)

  MySQL allowed an authenticated user to access a table through a previously
  created MERGE table, even after the user\'s privileges were revoked from
  the original table, which might violate intended security policy. This is
  addressed by allowing the MERGE storage engine to be disabled, which can
  be done by running mysqld with the "--skip-merge" option. (CVE-2006-4031)

  MySQL evaluated arguments in the wrong security context, which allowed an
  authenticated user to gain privileges through a routine that had been made
  available using "GRANT EXECUTE". (CVE-2006-4227)

  Multiple flaws in MySQL allowed an authenticated user to cause the MySQL
  daemon to crash via crafted SQL queries. This only caused a temporary
  denial of service, as the MySQL daemon is automatically restarted after the
  crash. (CVE-2006-7232, CVE-2007-1420, CVE-2007-2583)

  As well, these updated packages fix the following bugs:

  * a separate counter was used for "insert delayed" statements, which caused
  rows to be discarded. In these updated packages, "insert delayed"
  statements no longer use a separate counter, which resolves this issue.

  * due to a bug in the Native POSIX Thread Library, in certain situations,
  "flush tables" caused a deadlock on tables that had a read lock. The mysqld
  daemon had to be killed forcefully. Now, "COND_refresh" has been replaced
  with "COND_global_read_lock", which resolves this issue.

  * mysqld crashed if a query for an unsigned column type contained a
  negative value for a "WHERE [column] NOT IN" subquery.

  * in master and slave server situations, specifying "on duplicate key
  update" for "insert" statements did not update slave servers.

  * in the mysql client, empty strings were displayed as "NULL". For
  example, running "insert into [table-name] values (\' \');" resulted in a
  "NULL" entry being displayed when querying the table using "select * from
  [table-name];".

  * a bug in the optimizer code resulted in certain queries executing much
  slower than expected.

  * on 64-bit PowerPC architectures, MySQL did not calculate the thread stack
  size correctly, which could have caused MySQL to crash when overly-complex
  queries were used.

  Note: these updated packages upgrade MySQL to version 5.0.45. For a full
  list of bug fixes and enhancements, refer to the MySQL release notes:
  http://dev.mysql.com/doc/refman/5.0/en/releasenotes-cs-5-0.html

  All mysql users are advised to upgrade to these updated packages, which
  resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0364.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-0903", "CVE-2006-4031", "CVE-2006-4227", "CVE-2006-7232", "CVE-2007-1420", "CVE-2007-2583", "CVE-2007-2691", "CVE-2007-2692", "CVE-2007-3781", "CVE-2007-3782");
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

if ( rpm_check( reference:"mysql-5.0.45-7.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-5.0.45-7.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-5.0.45-7.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-server-5.0.45-7.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-test-5.0.45-7.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

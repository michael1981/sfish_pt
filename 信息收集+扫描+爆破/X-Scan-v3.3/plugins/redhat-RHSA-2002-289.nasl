#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12340);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2002-1376", "CVE-2002-1373", "CVE-2002-1374", "CVE-2002-1375");

 script_name(english:"RHSA-2002-289: mysql");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the patch for the advisory RHSA-2002-289");
 
 script_set_attribute(attribute:"description", value:
'
  Updated packages are available for Red Hat Linux Advanced Server 2.1 that
  fix
  security vulnerabilities found in the MySQL server.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  MySQL is a multi-user, multi-threaded SQL database server. While auditing
  MySQL, Stefan Esser found security vulnerabilities that can be used to
  crash the server or allow MySQL users to gain privileges.

  A signed integer vulnerability in the COM_TABLE_DUMP package for MySQL
  3.x to 3.23.53a, and 4.x to 4.0.5a, allows remote attackers to cause a
  denial of service (crash or hang) in mysqld by causing large negative
  integers to be provided to a memcpy call. (CVE-2002-1373)

  The COM_CHANGE_USER command in MySQL 3.x to 3.23.53a, and 4.x to
  4.0.5a, allows a remote attacker to gain privileges via a brute force
  attack using a one-character password, which causes MySQL to only compare
  the provided password against the first character of the real
  password. (CVE-2002-1374)

  The COM_CHANGE_USER command in MySQL 3.x to 3.23.53a, and 4.x to
  4.0.5a, allows remote attackers to execute arbitrary code via a long
  response. (CVE-2002-1375)

  The MySQL client library (libmysqlclient) in MySQL 3.x to 3.23.53a, and 4.x
  to 4.0.5a, does not properly verify length fields for certain responses
  in the read_rows or read_one_row routines, which allows a malicious server
  to cause a denial of service and possibly execute arbitrary
  code. (CVE-2002-1376)

  Red Hat Linux Advanced Server 2.1 contains versions of MySQL that are
  vulnerable to these issues. All users of MySQL are advised to upgrade to
  these errata packages containing MySQL 3.23.54a which is not vulnerable to
  these issues.
');
 script_set_attribute(attribute:"see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-289.html");
 script_set_attribute(attribute:"solution", value: "Get the newest RedHat updates.");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_end_attributes();
 
 script_summary(english: "Check for the version of the mysql packages"); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks"); 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mysql-3.23.54a-3.72", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.54a-3.72", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-server-3.23.54a-3.72", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host is not affected");

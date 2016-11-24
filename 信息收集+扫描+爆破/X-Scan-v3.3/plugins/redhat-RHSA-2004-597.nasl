
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15536);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-597: mysql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-597");
 script_set_attribute(attribute: "description", value: '
  Updated mysql packages that fix various security issues, as well as a
  number of bugs, are now available for Red Hat Enterprise Linux 2.1.

  MySQL is a multi-user, multi-threaded SQL database server.

  A number security issues that affect the mysql server have been reported:

  Oleksandr Byelkin discovered that "ALTER TABLE ... RENAME" checked
  the CREATE/INSERT rights of the old table instead of the new one. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-0835 to this issue.

  Lukasz Wojtow discovered a buffer overrun in the mysql_real_connect
  function. In order to exploit this issue an attacker would need to force
  the use of a malicious DNS server (CAN-2004-0836).

  Dean Ellis discovered that multiple threads ALTERing the same (or
  different) MERGE tables to change the UNION could cause the server to crash
  or stall (CAN-2004-0837).

  Sergei Golubchik discovered that if a user is granted privileges to a
  database with a name containing an underscore ("_"), the user also gains
  the ability to grant privileges to other databases with similar names
  (CAN-2004-0957).

  Additionally, the following minor temporary file vulnerabilities were
  discovered:

  - Stan Bubroski and Shaun Colley found a temporary file vulnerability in
  the mysqlbug script (CAN-2004-0381).
  - A temporary file vulnerability was discovered in mysqld_multi
  (CAN-2004-0388).
  - Jeroen van Wolffelaar discovered an temporary file vulnerability in the
  mysqlhotcopy script when using the scp method (CAN-2004-0457).

  All users of mysql should upgrade to these updated packages, which resolve
  these issues and also include fixes for a number of small bugs.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-597.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0381", "CVE-2004-0388", "CVE-2004-0457", "CVE-2004-0835", "CVE-2004-0836", "CVE-2004-0837", "CVE-2004-0957");
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

if ( rpm_check( reference:"mysql-3.23.58-1.72.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.58-1.72.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-server-3.23.58-1.72.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

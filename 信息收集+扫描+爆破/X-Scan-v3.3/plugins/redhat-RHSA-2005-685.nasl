
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19993);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-685: mysql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-685");
 script_set_attribute(attribute: "description", value: '
  Updated mysql packages that fix a temporary file flaw and a number of bugs
  are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
  client/server implementation consisting of a server daemon (mysqld)
  and many different client programs and libraries.

  An insecure temporary file handling bug was found in the mysql_install_db
  script. It is possible for a local user to create specially crafted files
  in /tmp which could allow them to execute arbitrary SQL commands during
  database installation. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-1636 to this issue.

  These packages update mysql to version 4.1.12, fixing a number of problems.
  Also, support for SSL-encrypted connections to the database server is now
  provided.

  All users of mysql are advised to upgrade to these updated packages.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-685.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1636");
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

if ( rpm_check( reference:"mysql-4.1.12-3.RHEL4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-4.1.12-3.RHEL4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-4.1.12-3.RHEL4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-server-4.1.12-3.RHEL4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

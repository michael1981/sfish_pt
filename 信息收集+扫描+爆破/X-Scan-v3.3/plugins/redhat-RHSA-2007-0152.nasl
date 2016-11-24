
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24951);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0152: mysql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0152");
 script_set_attribute(attribute: "description", value: '
  Updated mysql packages that fix a security flaw are now available for Red
  Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red Hat
  Security Response Team.

  MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
  client/server implementation consisting of a server daemon (mysqld) and
  many different client programs and libraries.

  A flaw was found in the way MySQL handled case sensitive database names. A
  user with the ability to create databases could gain unauthorized access to
  other databases hosted by the MySQL server. (CVE-2006-4226)

  This flaw does not affect the version of MySQL distributed with Red Hat
  Enterprise Linux 2.1, 3, or 5.

  All users of the MySQL server are advised to upgrade to these updated
  packages, which contain a backported patch which fixes this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0152.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4226");
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

if ( rpm_check( reference:"mysql-4.1.20-2.RHEL4.1", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-4.1.20-2.RHEL4.1", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-4.1.20-2.RHEL4.1", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-server-4.1.20-2.RHEL4.1", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

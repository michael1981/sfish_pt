#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17981);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");

 script_name(english: "RHSA-2005-348: mysql");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the patch for the advisory RHSA-2005-348");
script_set_attribute(attribute:"description", value: 
'

  Updated mysql-server packages that fix several vulnerabilities are now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  MySQL is a multi-user, multi-threaded SQL database server.

  This update fixes several security risks in the MySQL server.

  Stefano Di Paola discovered two bugs in the way MySQL handles user-defined
  functions. A user with the ability to create and execute a user defined
  function could potentially execute arbitrary code on the MySQL server. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the names CVE-2005-0709 and CVE-2005-0710 to these issues.

  Stefano Di Paola also discovered a bug in the way MySQL creates temporary
  tables. A local user could create a specially crafted symlink which could
  result in the MySQL server overwriting a file which it has write access to.
  The Common Vulnerabilities and Exposures project has assigned the name
  CVE-2005-0711 to this issue.

  All users of the MySQL server are advised to upgrade to these updated
  packages, which contain fixes for these issues.
');
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute: "solution", value: "Get the newest RedHat updates.");
 script_set_attribute(attribute: "see_also", value:
"http://rhn.redhat.com/errata/RHSA-2005-348.html");
 script_end_attributes();

 
 script_summary(english: "Check for the version of the mysql packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mysql-server-3.23.58-16.RHEL3.1", release:"RHEL3") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host in not affected");

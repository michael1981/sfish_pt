#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15631);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0835", "CVE-2004-0836", "CVE-2004-0837", "CVE-2004-0957");

 script_name(english:"RHSA-2004-611: mysql");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the patch for the advisory RHSA-2004-611");
 
 script_set_attribute(attribute:"description", value:
'

  An updated mysql-server package that fixes various security issues is now
  available in the Red Hat Enterprise Linux 3 Extras channel of Red Hat
  Network.

  MySQL is a multi-user, multi-threaded SQL database server.

  A number of security issues that affect the mysql-server package have been
  reported. Although Red Hat Enterprise Linux 3 does not ship with the
  mysql-server package, the affected package is available from the Red Hat
  Network Extras channel.

  Oleksandr Byelkin discovered that "ALTER TABLE ... RENAME" checked
  the CREATE/INSERT rights of the old table instead of the new one. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0835 to this issue.

  Lukasz Wojtow discovered a buffer overrun in the mysql_real_connect
  function. In order to exploit this issue an attacker would need to force
  the use of a malicious DNS server (CVE-2004-0836).

  Dean Ellis discovered that multiple threads ALTERing the same (or
  different) MERGE tables to change the UNION could cause the server to crash
  or stall (CVE-2004-0837).

  Sergei Golubchik discovered that if a user is granted privileges to a
  database with a name containing an underscore ("_"), the user also gains
  the ability to grant privileges to other databases with similar names
  (CVE-2004-0957).

  Users of mysql-server should upgrade to these erratum packages, which
  correct these issues.
');
 script_set_attribute(attribute:"see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-611.html");
 script_set_attribute(attribute:"solution", value: "Get the newest RedHat updates.");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
if ( rpm_check( reference:"mysql-server-3.23.58-2.3", release:"RHEL3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host is not affected");

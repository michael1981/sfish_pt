
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-554
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24106);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 4 2006-554: mysql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-554 (mysql)");
 script_set_attribute(attribute: "description", value: "MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries. The base package
contains the MySQL client programs, the client shared libraries, and
generic MySQL files.

Update Information:

4.1.19 fixes several moderate-severity security issues: see CVE-2006-0903 CVE-2
006-1516
CVE-2006-1517 CVE-2006-1518, also our bugs 180467 180639 182025 183261 190866 1
90868
190870

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-0903", "CVE-2006-1518");
script_summary(english: "Check for the version of the mysql package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mysql-4.1.19-1.FC4.1", release:"FC4") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

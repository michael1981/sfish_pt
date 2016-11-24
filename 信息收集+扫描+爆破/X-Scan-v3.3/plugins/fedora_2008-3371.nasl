
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3371
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32099);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-3371: dbmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3371 (dbmail)");
 script_set_attribute(attribute: "description", value: "Dbmail is the name of a group of programs that enable the possiblilty of
storing and retrieving mail messages from a database.

Currently dbmail supports the following database backends:
MySQL
PostgreSQL

SQLite


Please see /usr/share/doc/dbmail-*/README.fedora for specific information on
installation and configuration in Fedora.

-
Update Information:

Fix possible authentication bypass in authldap authentication module when dbmai
l
is used with LDAP servers allowing anonymous logins - CVE-2007-6714 (#443019).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-6714");
script_summary(english: "Check for the version of the dbmail package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"dbmail-2.2.9-1.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

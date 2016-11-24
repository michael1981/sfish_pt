
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-4245
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32410);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-4245: dbmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-4245 (dbmail)");
 script_set_attribute(attribute: "description", value: "Dbmail is the name of a group of programs that enable the possiblilty of
storing and retrieving mail messages from a database.

Currently dbmail supports the following database backends:
MySQL
PostgreSQL

SQLite


Please see /usr/share/doc/dbmail-*/README.fedora for specific information on
installation and configuration in Fedora.

-
ChangeLog:


Update information :

* Thu Apr 24 2008 Bernard Johnson <bjohnson symetrix com> - 2.2.9-1
- v 2.2.9
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

if ( rpm_check( reference:"dbmail-2.2.9-1.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-11258
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35099);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-11258: gallery2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-11258 (gallery2)");
 script_set_attribute(attribute: "description", value: "The base Gallery 2 installation - the equivalent of upstream's -minimal
package.  This package requires a database to be operational.  Acceptable
database backends include MySQL v 3.x, MySQL v 4.x, PostgreSQL v 7.x,
PostgreSQL v 8.x, Oracle 9i, Oracle 10g, DB2, and MS SQL Server.  All given
package versions are minimums, greater package versions are acceptable.

-
Update Information:

New version, multiple fixes.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3662", "CVE-2008-4129", "CVE-2008-4130");
script_summary(english: "Check for the version of the gallery2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gallery2-2.3-1.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

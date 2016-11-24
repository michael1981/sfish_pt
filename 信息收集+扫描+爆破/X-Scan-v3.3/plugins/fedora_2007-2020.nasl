
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2020
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27746);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-2020: gallery2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2020 (gallery2)");
 script_set_attribute(attribute: "description", value: "The base Gallery 2 installation - the equivalent of upstream's -minimal
package.  This package requires a database to be operational.  Acceptable
database backends include MySQL v 3.x, MySQL v 4.x, PostgreSQL v 7.x,
PostgreSQL v 8.x, Oracle 9i, Oracle 10g, DB2, and MS SQL Server.  All given
package versions are minimums, greater package versions are acceptable.

-
Update Information:

Security fix release for Gallery 2.2 series.

CVE text:
Multiple unspecified vulnerabilities in Gallery before 2.2.3 allow
attackers to (1) rename items, (2) read and modify item properties, or (3) loc
k and replace items via unknown vectors in (a) the WebDAV module; and (4) edit
unspecified data files using 'linked items' in (a) WebDAV and (b) Reupload modu
les.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-4650");
script_summary(english: "Check for the version of the gallery2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gallery2-2.2-0.7.svn20070831.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

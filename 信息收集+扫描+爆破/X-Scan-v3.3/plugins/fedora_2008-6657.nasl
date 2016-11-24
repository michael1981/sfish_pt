
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6657
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33555);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-6657: mantis");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6657 (mantis)");
 script_set_attribute(attribute: "description", value: "Mantis is a web-based bugtracking system.
It is written in the PHP scripting language and requires the MySQL
database and a webserver. Mantis has been installed on Windows, MacOS,
OS/2, and a variety of Unix operating systems. Any web browser should
be able to function as a client.

Documentation can be found in: /usr/share/doc/mantis-1.1.2

When the package has finished installing, you will need to perform some
additional configuration steps; these are described in:
/usr/share/doc/mantis-1.1.2/README.Fedora

-
Update Information:

Update to upstream version 1.1.2, fixing following security issues:    -
0008974: XSS Vulnerability in filters    - 0008975: CSRF Vulnerabilities in
user_create (CVE-2008-2276)  - 0008976: Remote Code Execution in adm_config
-
0009154: arbitrary file inclusion through user preferences page    See upstream
changelog for details on all bugs fixed in new upstream version:
[9]http://www.mantisbt.org/bugs/changelog_page.php
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2276");
script_summary(english: "Check for the version of the mantis package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mantis-1.1.2-1.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

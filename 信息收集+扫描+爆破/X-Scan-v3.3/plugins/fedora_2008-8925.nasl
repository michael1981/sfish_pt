
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-8925
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34451);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-8925: mantis");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-8925 (mantis)");
 script_set_attribute(attribute: "description", value: "Mantis is a web-based bugtracking system.
It is written in the PHP scripting language and requires the MySQL
database and a webserver. Mantis has been installed on Windows, MacOS,
OS/2, and a variety of Unix operating systems. Any web browser should
be able to function as a client.

Documentation can be found in: /usr/share/doc/mantis-1.1.4

When the package has finished installing, you will need to perform some
additional configuration steps; these are described in:
/usr/share/doc/mantis-1.1.4/README.Fedora

-
Update Information:

This releases fixes CVE-2008-3102 and a bunch of other issues. For the full
changelog, please check: [9]http://www.mantisbt.org/bugs/changelog_page.php
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3102");
script_summary(english: "Check for the version of the mantis package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mantis-1.1.4-1.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

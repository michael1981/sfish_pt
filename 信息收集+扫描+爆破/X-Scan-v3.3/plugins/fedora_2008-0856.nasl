
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-0856
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(30077);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-0856: mantis");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-0856 (mantis)");
 script_set_attribute(attribute: "description", value: "Mantis is a web-based bugtracking system.
It is written in the PHP scripting language and requires the MySQL
database and a webserver. Mantis has been installed on Windows, MacOS,
OS/2, and a variety of Unix operating systems. Any web browser should
be able to function as a client.

Documentation can be found in: /usr/share/doc/mantis-1.1.1

When the package has finished installing, you will need to perform some
additional configuration steps; these are described in:
/usr/share/doc/mantis-1.1.1/README.Fedora

-
Update Information:

New upstream release, also fixes a minor security issue detailed in:
[9]http://bugs.mantisbt.org/view.php?id=8756
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the mantis package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mantis-1.1.1-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

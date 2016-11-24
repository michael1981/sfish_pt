
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-1057
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35466);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2009-1057: dia");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-1057 (dia)");
 script_set_attribute(attribute: "description", value: "The Dia drawing program is designed to be like the Windows(TM) Visio
program.  Dia can be used to draw different types of diagrams, and
includes support for UML static structure diagrams (class diagrams),
entity relationship modeling, and network diagrams.  Dia can load and
save diagrams to a custom file format, can load and save in .xml format,
and can export to PostScript(TM).

-
Update Information:

Filter out untrusted python modules search path to remove the possibility to ru
n
arbitrary code on the user's system if there is a python file in dia's working
directory named the same as one that dia's python scripts try to import.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the dia package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"dia-0.96.1-7.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

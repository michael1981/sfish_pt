
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(30194);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for Geronimo (geronimo-4967)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch geronimo-4967");
 script_set_attribute(attribute: "description", value: "A chown in the geronimo init script could change ownership
of directories it did not own, due to following symlinks.
The default setup would corrupt /var/tmp on start.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch geronimo-4967");
script_end_attributes();

script_summary(english: "Check for the geronimo-4967 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"geronimo-1.0-16.11", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"geronimo-jetty-servlet-container-1.0-16.11", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"geronimo-tomcat-servlet-container-1.0-16.11", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

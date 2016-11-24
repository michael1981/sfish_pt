
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(30193);
 script_version ("$Revision: 1.4 $");
 script_name(english: "SuSE Security Update:  geronimo: Fixed chown in startscript (geronimo-4957)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch geronimo-4957");
 script_set_attribute(attribute: "description", value: "A chown in the geronimo init script could change ownership
of directories it did not own, due to following symlinks.
The default setup would corrupt /var/tmp on start.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch geronimo-4957");
script_end_attributes();

script_summary(english: "Check for the geronimo-4957 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"geronimo-1.1-138.5", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"geronimo-jetty-servlet-container-1.1-138.5", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"geronimo-tomcat-servlet-container-1.1-138.5", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

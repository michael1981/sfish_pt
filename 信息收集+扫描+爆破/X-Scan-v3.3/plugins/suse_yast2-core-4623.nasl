
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29613);
 script_version ("$Revision: 1.8 $");
 script_name(english: "SuSE Security Update:  Security update for YaST2 (yast2-core-4623)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch yast2-core-4623");
 script_set_attribute(attribute: "description", value: "This update fixes a security bug in yast2-core that allowed
local attackers to provide malicious yast2 modules to yast2
that are executed with root privileges. To trigger this
vulnerability root has to execute yast2 in an untrusted
directory (i.e. /tmp).  Thanks to Stefan Nordhausen for
reporting this to us.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch yast2-core-4623");
script_end_attributes();

script_summary(english: "Check for the yast2-core-4623 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"yast2-core-2.13.41-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"yast2-core-devel-2.13.41-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"yast2-core-2.13.41-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

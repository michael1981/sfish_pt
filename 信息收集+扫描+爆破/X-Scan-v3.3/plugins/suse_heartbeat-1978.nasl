
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29459);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for heartbeat (heartbeat-1978)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch heartbeat-1978");
 script_set_attribute(attribute: "description", value: "This update fixes both a local and a remote denial of
service attack within heartbeat, as well as numerous other
bugs in the messaging and membership layer, GUI, Cluster
Resource Manager, Local Resource Manager and Resource
Agents.

");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch heartbeat-1978");
script_end_attributes();

script_summary(english: "Check for the heartbeat-1978 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"heartbeat-2.0.7-1.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"heartbeat-cmpi-2.0.7-1.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"heartbeat-ldirectord-2.0.7-1.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"heartbeat-pils-2.0.7-1.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"heartbeat-stonith-2.0.7-1.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

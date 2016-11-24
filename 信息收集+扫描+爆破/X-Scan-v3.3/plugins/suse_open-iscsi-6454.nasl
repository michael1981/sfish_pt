
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42026);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  open-iscsi security update (open-iscsi-6454)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch open-iscsi-6454");
 script_set_attribute(attribute: "description", value: "The iscsi_discovery tool created predictable temporary
files which potentially allowed attackers to overwrite
system files (CVE-2009-1297 ).
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch open-iscsi-6454");
script_end_attributes();

script_cve_id("CVE-2009-1297");
script_summary(english: "Check for the open-iscsi-6454 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"open-iscsi-2.0.866-15.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

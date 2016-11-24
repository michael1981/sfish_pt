
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41151);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for subdomain-parser (11787)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 11787");
 script_set_attribute(attribute: "description", value: 'The following patch supports new language features in
AppArmor which have been added to improve the confinement
provided to applications executing other applications will
confined by AppArmor. Two new execute modifiers: \'P\' and \'U\'
are provided and are flavors of the exisiting \'p\' and \'u\'
modifiers but indicate that the enviroment should be
stripped across the execute transition. A new permission \'m\'
is required when an application executes the mmap(2) with
the prot arg PROT_EXEC.
This is a reissue of a previous update due to RPM release
number problems.
');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch 11787");
script_end_attributes();

script_summary(english: "Check for the security advisory #11787");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"subdomain-parser-1.2-42.2", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"subdomain-parser-common-1.2-42.2", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"subdomain-profiles-1.2_SLES9-21.2", release:"SUSE9", cpu: "noarch") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"subdomain-utils-1.2-23.2", release:"SUSE9", cpu: "noarch") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"yast2-subdomain-1.2-11.3", release:"SUSE9", cpu: "noarch") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

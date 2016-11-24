
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(40161);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  yast2-backup (2008-10-30)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for yast2-backup");
 script_set_attribute(attribute: "description", value: "This updated of yast2-backup fixes a sellcode injection
vulnerability and improves handling of symlinks for the
backup process.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for yast2-backup");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=421214");
script_end_attributes();

script_summary(english: "Check for the yast2-backup package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"yast2-backup-2.16.6-0.1", release:"SUSE11.0", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

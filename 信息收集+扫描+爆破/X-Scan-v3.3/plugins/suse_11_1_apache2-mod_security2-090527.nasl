
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40188);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.1 Security Update:  apache2-mod_security2 (2009-05-27)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for apache2-mod_security2");
 script_set_attribute(attribute: "description", value: "A remote DoS condition in the multipart processing of
apache2-mod_security2 has been fixed. No CVE has been
assigned to this issue yet.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for apache2-mod_security2");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=487751");
script_end_attributes();

script_summary(english: "Check for the apache2-mod_security2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"apache2-mod_security2-2.5.6-1.25.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"apache2-mod_security2-2.5.6-1.25.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

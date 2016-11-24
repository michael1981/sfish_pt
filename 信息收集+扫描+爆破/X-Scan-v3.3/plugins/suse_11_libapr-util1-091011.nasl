
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42234);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  libapr-util1 (2009-10-11)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for libapr-util1");
 script_set_attribute(attribute: "description", value: "This update of libapr-util1 and libapr1 fixes multiple
integer overflows that could probably be used to execute
arbitrary code remotely. (CVE-2009-2412)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for libapr-util1");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=529591");
script_end_attributes();

 script_cve_id("CVE-2009-2412");
script_summary(english: "Check for the libapr-util1 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libapr-util1-1.3.4-12.20.2", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libapr1-1.3.3-11.16.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

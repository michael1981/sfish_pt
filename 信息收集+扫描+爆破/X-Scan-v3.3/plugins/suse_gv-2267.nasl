
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29454);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for gv (gv-2267)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gv-2267");
 script_set_attribute(attribute: "description", value: "A stackoverflow in the postscript viewer gv could be used
to exploited
 to execute code, if the user could be tricked
into viewing a prepared
 postscript file. (CVE-2006-5864)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch gv-2267");
script_end_attributes();

script_cve_id("CVE-2006-5864");
script_summary(english: "Check for the gv-2267 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"gv-3.5.8-1156.5", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

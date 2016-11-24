
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29782);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for clamav (clamav-4836)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch clamav-4836");
 script_set_attribute(attribute: "description", value: "This version upgrade to 0.92  fixes numerous flaws
including some security problems (CVE-2007-6335,
CVE-2007-6336, CVE-2007-6337).

Please note that the version number of the clamav library
has changed. Programs linked against libclamav therefore
need to be updated as well.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch clamav-4836");
script_end_attributes();

script_cve_id("CVE-2007-6335", "CVE-2007-6336", "CVE-2007-6337");
script_summary(english: "Check for the clamav-4836 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"clamav-0.92-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

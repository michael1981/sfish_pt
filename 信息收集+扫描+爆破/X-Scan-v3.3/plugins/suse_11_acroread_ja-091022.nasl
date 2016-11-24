
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42251);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  acroread_ja (2009-10-22)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for acroread_ja");
 script_set_attribute(attribute: "description", value: "Adobe Reader has been updated to fix numerous security
vulnerabilities. Some of the vulnerabilities allowed
attackers to potentially execute arbitrary code on the
victim's system via specially crafted PDF files.

(CVE-2007-0048, CVE-2007-0045, CVE-2009-2564,CVE-2009-2979,
CVE-2009-2980, CVE-2009-2981, CVE-2009-2982, CVE-2009-2983,
CVE-2009-2985, CVE-2009-2986, CVE-2009-2988, CVE-2009-2990,
CVE-2009-2991, CVE-2009-2992, CVE-2009-2993, CVE-2009-2994,
CVE-2009-2996, CVE-2009-2997, CVE-2009-2998, CVE-2009-3431,
CVE-2009-3458, CVE-2009-3459, CVE-2009-3462)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for acroread_ja");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=546083");
script_end_attributes();

 script_cve_id("CVE-2007-0045", "CVE-2007-0048", "CVE-2009-2564", "CVE-2009-2979", "CVE-2009-2980", "CVE-2009-2981", "CVE-2009-2982", "CVE-2009-2983", "CVE-2009-2985", "CVE-2009-2986", "CVE-2009-2988", "CVE-2009-2990", "CVE-2009-2991", "CVE-2009-2992", "CVE-2009-2993", "CVE-2009-2994", "CVE-2009-2996", "CVE-2009-2997", "CVE-2009-2998", "CVE-2009-3431", "CVE-2009-3458", "CVE-2009-3459", "CVE-2009-3462");
script_summary(english: "Check for the acroread_ja package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"acroread_ja-8.1.7-0.1.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

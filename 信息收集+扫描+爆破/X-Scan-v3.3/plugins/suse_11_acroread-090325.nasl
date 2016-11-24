
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41362);
 script_version("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  acroread (2009-03-25)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for acroread");
 script_set_attribute(attribute: "description", value: "Multiple flaws in the JBIG2 decoder and the JavaScript
engine of the Adobe Reader allowed attackers to crash
acroread or even execute arbitrary code by tricking users
into opening specially crafted PDF files.

(CVE-2009-0658, CVE-2009-0927, CVE-2009-0193,
CVE-2009-0928, CVE-2009-1061, CVE-2009-1062)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for acroread");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=488619");
script_end_attributes();

 script_cve_id("CVE-2009-0193", "CVE-2009-0658", "CVE-2009-0927", "CVE-2009-0928", "CVE-2009-1061", "CVE-2009-1062");
script_summary(english: "Check for the acroread package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"acroread-8.1.4-0.9.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

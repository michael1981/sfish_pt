
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39985);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  horde (2009-03-19)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for horde");
 script_set_attribute(attribute: "description", value: "Version update to horde 3.1.9 fixes a cross-site-scripting
(XSS) issue (CVE-2008-5917) and an include file problem
(CVE-2009-0932).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for horde");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=467887");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=348297");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=470086");
script_end_attributes();

 script_cve_id("CVE-2008-5917", "CVE-2009-0932");
script_summary(english: "Check for the horde package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"horde-3.1.9-0.1", release:"SUSE11.0", cpu:"noarch") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

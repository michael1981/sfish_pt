
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33898);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  rdesktop: fixed CVE-2008-1801, CVE-2008-1802 and CVE-2008-1803 (rdesktop-5271)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch rdesktop-5271");
 script_set_attribute(attribute: "description", value: "Multiple problems have been fixed in rdesktop.
CVE-2008-1801, CVE-2008-1802 and CVE-2008-1803 have been
assigned to this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch rdesktop-5271");
script_end_attributes();

script_cve_id("CVE-2008-1801", "CVE-2008-1802", "CVE-2008-1803");
script_summary(english: "Check for the rdesktop-5271 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"rdesktop-1.5.0-79.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

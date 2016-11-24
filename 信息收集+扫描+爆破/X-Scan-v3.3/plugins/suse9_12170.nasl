
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41215);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for XFree86 (12170)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 12170");
 script_set_attribute(attribute: "description", value: 'This update fixes multiple vulnerabilities reported by iDefense:
CVE-2008-2360 - RENDER Extension heap buffer overflow
CVE-2008-2361 - RENDER Extension crash
CVE-2008-2362 - RENDER Extension memory corruption 
CVE-2008-1379 - MIT-SHM arbitrary memory read
CVE-2008-1377 - RECORD and Security extensions memory corruption
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch 12170");
script_end_attributes();

script_cve_id("CVE-2008-1377","CVE-2008-1379","CVE-2008-2360","CVE-2008-2361","CVE-2008-2362");
script_summary(english: "Check for the security advisory #12170");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"XFree86-Xnest-4.3.99.902-43.96", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"XFree86-Xprt-4.3.99.902-43.96", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"XFree86-Xvfb-4.3.99.902-43.96", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"XFree86-Xvnc-4.3.99.902-43.96", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"XFree86-server-4.3.99.902-43.96", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

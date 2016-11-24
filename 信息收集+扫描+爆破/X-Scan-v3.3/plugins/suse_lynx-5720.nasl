
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34984);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  VUL-0: lynx: lynxcgi command execution possible (lynx-5720)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch lynx-5720");
 script_set_attribute(attribute: "description", value: "This update of lynx fixes a security bug that can be
exploited by remote attackers to execute arbitrary commands
when advanced mode is enabled and lynx is used as URL
handler (CVE-2008-4690)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch lynx-5720");
script_end_attributes();

script_cve_id("CVE-2008-4690");
script_summary(english: "Check for the lynx-5720 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"lynx-2.8.6-48.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

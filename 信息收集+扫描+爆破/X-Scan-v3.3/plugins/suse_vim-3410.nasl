
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27474);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  vim security update (vim-3410)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch vim-3410");
 script_set_attribute(attribute: "description", value: "Files with VIM modelines could call some unsafe VIM
functions (CVE-2007-2438). Modelines are disabled in the
default config (/etc/vimrc) of openSUSE though.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch vim-3410");
script_end_attributes();

script_cve_id("CVE-2007-2438");
script_summary(english: "Check for the vim-3410 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gvim-7.0-36", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"vim-7.0-36", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"vim-enhanced-7.0-36", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

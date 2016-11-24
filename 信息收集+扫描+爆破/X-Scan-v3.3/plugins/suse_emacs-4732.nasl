
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28355);
 script_version ("$Revision: 1.4 $");
 script_name(english: "SuSE Security Update:  emacs: Fix for buffer overflow (emacs-4732)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch emacs-4732");
 script_set_attribute(attribute: "description", value: "This update fixes a buffer overflow in emacs that can be
triggered over the command-line.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch emacs-4732");
script_end_attributes();

script_summary(english: "Check for the emacs-4732 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"emacs-22.1-40.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"emacs-el-22.1-40.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"emacs-info-22.1-40.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"emacs-nox-22.1-40.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"emacs-x11-22.1-40.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

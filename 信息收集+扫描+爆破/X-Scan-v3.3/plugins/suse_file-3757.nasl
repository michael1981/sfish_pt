
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27216);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  file: This update fixes a vulnerability in file (file-3757)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch file-3757");
 script_set_attribute(attribute: "description", value: "This update fixes an integer overflow in function
file_printf() of file. This bug can be used to execute
arbitrary code. (CVE-2007-2799)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch file-3757");
script_end_attributes();

script_cve_id("CVE-2007-2799");
script_summary(english: "Check for the file-3757 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"file-4.16-15.13", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"file-32bit-4.16-15.13", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"file-64bit-4.16-15.13", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"file-devel-4.16-15.13", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

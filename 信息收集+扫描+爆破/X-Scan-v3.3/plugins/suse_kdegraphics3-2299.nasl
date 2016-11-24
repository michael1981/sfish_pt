
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27286);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  kdegraphics3: Fixed EXIF problems in kfile_jpeg plugin. (kdegraphics3-2299)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kdegraphics3-2299");
 script_set_attribute(attribute: "description", value: "The KFILE JPEG plugin that is responsible for displaying
meta-data of JPEG files was affected by some old common
vulnerabilities in EXIF handling.

A JPEG file could be prepared with an EXIF section with
endless recursion that would overflow the stack and cause
the plugin and so the image browser (konqueror, digikam or
other kfile users) to crash.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch kdegraphics3-2299");
script_end_attributes();

script_summary(english: "Check for the kdegraphics3-2299 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kdegraphics3-3.5.1-23.9", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29958);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  libexif: Fixed 2 security problems in the EXIF loader. (libexif-4886)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libexif-4886");
 script_set_attribute(attribute: "description", value: "Two bugs in libexif were identified by a Google Security
Audit done by Meder Kydyraliev.

CVE-2007-6351: Loading EXIF data could be used to cause a
infinite recursion and crash CVE-2007-6352: Integer
overflows in the thumbnail handler could be used to
overflow buffers and potentially execute code or crash a
program using libexif.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch libexif-4886");
script_end_attributes();

script_cve_id("CVE-2007-6351", "CVE-2007-6352");
script_summary(english: "Check for the libexif-4886 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libexif-0.6.16-23.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libexif-32bit-0.6.16-23.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libexif-64bit-0.6.16-23.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libexif-devel-0.6.16-23.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

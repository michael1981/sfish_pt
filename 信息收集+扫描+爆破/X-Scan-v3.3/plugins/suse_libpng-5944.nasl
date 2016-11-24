
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35553);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  libpng: fix for png_check_keyword function (libpng-5944)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libpng-5944");
 script_set_attribute(attribute: "description", value: "This update of libpng fixes the function
png_check_keyword() that allowed setting arbitrary bytes in
the process memory to 0. (CVE-2008-5907)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch libpng-5944");
script_end_attributes();

script_cve_id("CVE-2008-5907");
script_summary(english: "Check for the libpng-5944 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libpng-1.2.18-15.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpng-32bit-1.2.18-15.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpng-64bit-1.2.18-15.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.18-15.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpng-devel-32bit-1.2.18-15.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpng-devel-64bit-1.2.18-15.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

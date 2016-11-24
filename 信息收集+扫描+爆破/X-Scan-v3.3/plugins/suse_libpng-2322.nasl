
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27329);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  libpng: Security update to fix sPLT overflow. (libpng-2322)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libpng-2322");
 script_set_attribute(attribute: "description", value: "The sPLT chunk handling in libpng was incorrect and a
handcrafted
 PNG file could be use to cause an
out-of-bounds read, effectively
 crashing the PNG viewer or
webbrowser. (CVE-2006-5793)

Additionaly a 2 byte stackoverflow was fixed which we do
not believe
 to be exploitable. It will cause an abort of
the viewer or webbrowser
 in SUSE Linux 10.0 and newer due
to string overflow checking. (CVE-2006-3334)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch libpng-2322");
script_end_attributes();

script_cve_id("CVE-2006-5793", "CVE-2006-3334");
script_summary(english: "Check for the libpng-2322 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libpng-1.2.8-19.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpng-32bit-1.2.8-19.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpng-64bit-1.2.8-19.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.8-19.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpng-devel-32bit-1.2.8-19.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpng-devel-64bit-1.2.8-19.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

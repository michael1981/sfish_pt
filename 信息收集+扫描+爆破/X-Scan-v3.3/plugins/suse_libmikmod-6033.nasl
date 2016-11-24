
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35759);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  libmikmod security update (libmikmod-6033)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libmikmod-6033");
 script_set_attribute(attribute: "description", value: "Specially crafted XM files or playing mod files with
varying number of channels could crash applications using
libmikmod (CVE-2009-0179, CVE-2007-6720).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch libmikmod-6033");
script_end_attributes();

script_cve_id("CVE-2009-0179", "CVE-2007-6720");
script_summary(english: "Check for the libmikmod-6033 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libmikmod-3.1.11a-34.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmikmod-32bit-3.1.11a-34.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmikmod-64bit-3.1.11a-34.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmikmod-devel-3.1.11a-34.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

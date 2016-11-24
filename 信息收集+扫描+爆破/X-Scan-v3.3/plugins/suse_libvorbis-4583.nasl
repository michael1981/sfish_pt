
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27606);
 script_version ("$Revision: 1.4 $");
 script_name(english: "SuSE Security Update:  libvorbis security update (libvorbis-4583)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libvorbis-4583");
 script_set_attribute(attribute: "description", value: "Specially crafted OGG files could crash libvorbis or make
it run into an endless loop (CVE-2007-4029, CVE-2007-4065,
CVE-2007-4066).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch libvorbis-4583");
script_end_attributes();

script_cve_id("CVE-2007-4029", "CVE-2007-4065", "CVE-2007-4066");
script_summary(english: "Check for the libvorbis-4583 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libvorbis-1.1.2-35", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libvorbis-32bit-1.1.2-35", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libvorbis-64bit-1.1.2-35", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libvorbis-devel-1.1.2-35", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

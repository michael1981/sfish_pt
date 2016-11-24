
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27335);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  libvorbis: fix for an array boundary problem (libvorbis-3850)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libvorbis-3850");
 script_set_attribute(attribute: "description", value: "An array boundary problem within libvorbis was fixed.
CVE-2007-3106 has been assigned to this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch libvorbis-3850");
script_end_attributes();

script_cve_id("CVE-2007-3106");
script_summary(english: "Check for the libvorbis-3850 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libvorbis-1.1.2-33", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libvorbis-32bit-1.1.2-33", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libvorbis-64bit-1.1.2-33", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libvorbis-devel-1.1.2-33", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

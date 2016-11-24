
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31401);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  libcdio security update (libcdio-5059)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libcdio-5059");
 script_set_attribute(attribute: "description", value: "Long file names in ISO file systems with Joliet extension
could cause a buffer overflow in libcdio (CVE-2007-6613).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch libcdio-5059");
script_end_attributes();

script_cve_id("CVE-2007-6613");
script_summary(english: "Check for the libcdio-5059 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libcdio-0.77-18", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libcdio-32bit-0.77-18", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libcdio-64bit-0.77-18", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libcdio-devel-0.77-18", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

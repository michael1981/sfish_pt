
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35039);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  ndiswrapper: remote denial of service, maybe code execution (ndiswrapper-5833)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ndiswrapper-5833");
 script_set_attribute(attribute: "description", value: "The ndiswrapper was updated to fix multiple buffer
overflows that can be exploited over a connected WLAN by
using long ESSID stings. (CVE-2008-4395)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch ndiswrapper-5833");
script_end_attributes();

script_cve_id("CVE-2008-4395");
script_summary(english: "Check for the ndiswrapper-5833 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ndiswrapper-1.47-32.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-bigsmp-1.47_2.6.22.19_0.1-32.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-default-1.47_2.6.22.19_0.1-32.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-xen-1.47_2.6.22.19_0.1-32.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ndiswrapper-kmp-xenpae-1.47_2.6.22.19_0.1-32.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27416);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  quagga security update (quagga-1422)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch quagga-1422");
 script_set_attribute(attribute: "description", value: "It was possible to bypass RIPv2 authentication requirements
by using RIPv1. Since RIPv1 doesn't support authentication
at all this update introduces an option to switch off RIPv1
(CVE-2006-2223, CVE-2006-2224).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch quagga-1422");
script_end_attributes();

script_cve_id("CVE-2006-2223", "CVE-2006-2224");
script_summary(english: "Check for the quagga-1422 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"quagga-0.98.5-17.5", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

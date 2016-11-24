
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34025);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  openwsman: fixing multiple security issues (libwsman-devel-5531)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libwsman-devel-5531");
 script_set_attribute(attribute: "description", value: "This update of openwsman fixes several security
vulnerabilities found by the SuSE Security-Team:
- remote buffer overflows while decoding the HTTP basic
  authentication header (CVE-2008-2234)
- a possible SSL session replay attack affecting the client
  (depending on the configuration) (CVE-2008-2233)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch libwsman-devel-5531");
script_end_attributes();

script_cve_id("CVE-2008-2234", "CVE-2008-2233");
script_summary(english: "Check for the libwsman-devel-5531 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"openwsman-1.2.0-14.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openwsman-client-1.2.0-14.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openwsman-devel-1.2.0-14.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openwsman-server-1.2.0-14.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

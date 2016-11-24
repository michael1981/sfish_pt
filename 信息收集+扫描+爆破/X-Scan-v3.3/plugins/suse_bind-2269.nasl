
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27166);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  bind: Fixed DNSSEC RSA signature evasion problem (bind-2269)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch bind-2269");
 script_set_attribute(attribute: "description", value: "The RSA signature problem tracked by the Mitre CVE ID
CVE-2006-4339 also affects the DNSSEC implementation in the
BIND nameserver. This update fixes this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch bind-2269");
script_end_attributes();

script_cve_id("CVE-2006-4339");
script_summary(english: "Check for the bind-2269 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"bind-9.3.2-17.11", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"bind-libs-9.3.2-17.11", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"bind-libs-32bit-9.3.2-17.11", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"bind-libs-64bit-9.3.2-17.11", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"bind-utils-9.3.2-17.11", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

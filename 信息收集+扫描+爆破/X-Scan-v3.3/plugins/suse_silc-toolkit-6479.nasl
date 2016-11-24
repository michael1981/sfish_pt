
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42033);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  silc-toolkit: official update fixes several security issues (silc-toolkit-6479)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch silc-toolkit-6479");
 script_set_attribute(attribute: "description", value: "This update of slic-toolkit fixes stack-based overflow
while encoding a ASN.1 OID (CVE-2008-7159) and several
format string bugs (CVE-2009-3051, CVE-2008-7160). The
probability to exploit this issues to execute arbitrary
code is high.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch silc-toolkit-6479");
script_end_attributes();

script_cve_id("CVE-2008-7159", "CVE-2009-3051", "CVE-2008-7160");
script_summary(english: "Check for the silc-toolkit-6479 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"silc-toolkit-1.1.2-14.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"silc-toolkit-devel-1.1.2-14.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

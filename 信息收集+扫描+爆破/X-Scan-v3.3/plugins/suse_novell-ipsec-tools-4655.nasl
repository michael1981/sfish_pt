
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(30016);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  novell-ipsec-tools: Security update (novell-ipsec-tools-4655)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch novell-ipsec-tools-4655");
 script_set_attribute(attribute: "description", value: "This update fixes a security problem in novell-ipsec-tools:

CVE-2007-1841: Fix a DoS in isakmp_info_recv

and also a non-security bug with a crash in GSSAPI.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch novell-ipsec-tools-4655");
script_end_attributes();

script_cve_id("CVE-2007-1841");
script_summary(english: "Check for the novell-ipsec-tools-4655 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"novell-ipsec-tools-0.6.3-114.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"novell-ipsec-tools-devel-0.6.3-114.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27448);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Evasion attack in http_inspect preprocessor. (snort-1598)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch snort-1598");
 script_set_attribute(attribute: "description", value: "This update fixes an evasion attack on URL parsing. The 
faulty code is in the http_inspect preprocessor. 
(CVE-2006-2769)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch snort-1598");
script_end_attributes();

script_cve_id("CVE-2006-2769");
script_summary(english: "Check for the snort-1598 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"snort-2.4.4-10.4", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

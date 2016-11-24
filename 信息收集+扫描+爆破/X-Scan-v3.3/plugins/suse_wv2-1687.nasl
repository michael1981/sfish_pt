
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27480);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  wv2: Securityfix for missing boundary checks (wv2-1687)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch wv2-1687");
 script_set_attribute(attribute: "description", value: "The wv2 library was updated to fix some boundary checks 
which could be exploited by maliciously crafted files to 
access memory outside bounds and possibly execute arbitrary 
code. (CVE-2006-2197)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch wv2-1687");
script_end_attributes();

script_cve_id("CVE-2006-2197");
script_summary(english: "Check for the wv2-1687 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"wv2-0.2.2-21.2", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"wv2-devel-0.2.2-21.2", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

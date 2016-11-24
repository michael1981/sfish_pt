
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42029);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  opera: Update to version 10 to fix XML denial of service and SSL tampering problem (opera-6473)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch opera-6473");
 script_set_attribute(attribute: "description", value: "Opera version 10 includes at least security fixes for an
XML denial-of-service bug (CVE-2009-1234) and the 'SSL
tampering' attack (CVE-2009-2059, CVE-2009-2063,
CVE-2009-2067, CVE-2009-2070).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch opera-6473");
script_end_attributes();

script_cve_id("CVE-2009-1234", "CVE-2009-2059", "CVE-2009-2063", "CVE-2009-2067", "CVE-2009-2070");
script_summary(english: "Check for the opera-6473 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"opera-10.00-6.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

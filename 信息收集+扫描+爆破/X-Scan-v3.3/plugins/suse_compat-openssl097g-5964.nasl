
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35471);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  OpenSSL incorrect checks for malformed signatures (compat-openssl097g-5964)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch compat-openssl097g-5964");
 script_set_attribute(attribute: "description", value: "This update improves the verification of return values.
Prior to this udpate it was possible to bypass the
certification chain checks of openssl. (CVE-2008-5077)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch compat-openssl097g-5964");
script_end_attributes();

script_cve_id("CVE-2008-5077");
script_summary(english: "Check for the compat-openssl097g-5964 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"compat-openssl097g-0.9.7g-75.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"compat-openssl097g-32bit-0.9.7g-75.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"compat-openssl097g-64bit-0.9.7g-75.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

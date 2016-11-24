
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41312);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE9 Security Update:  Security update for ruby (12452)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 12452");
 script_set_attribute(attribute: "description", value: 'This update for ruby fixes the following security issues:
Improve return value checks for OpenSSL function OCSP_basic_verify() to refuse usage of revoked certificates. (CVE-2009-0642)
Increase  entropy of DNS identifiers to avoid spoofing attacks.(CVE-2008-3905)
Fix denial of service (DoS) vulnerability while parsing XML data.(CVE-2008-3790) 
Fix possible attack on algorithm complexity in function WEBrick::HTTP::DefaultFileHandler() while parsing HTTP requests or by using the regex engine to cause high CPU load. (CVE-2008-3656, CVE-2008-3443)
Improve ruby\'s access restriction code (CVE-2008-3655).
Improve safe-level handling using function DL.dlopen(). (CVE-2008-3657)
Improve big decimal handling (CVE-2009-1904).
Disable bypassing of HTTP basic authentication (authenticate_with_http_digest).
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch 12452");
script_end_attributes();

script_cve_id("CVE-2008-3443","CVE-2008-3655","CVE-2008-3656","CVE-2008-3657","CVE-2008-3790","CVE-2008-3905","CVE-2009-0642","CVE-2009-1904");
script_summary(english: "Check for the security advisory #12452");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ruby-1.8.1-42.27", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41101);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for gnutls (11228)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 11228");
 script_set_attribute(attribute: "description", value: 'A security problem in the GNU TLS library has been found:
If an RSA key with exponent 3 is used, the PKCS padding gets
removed before generating a hash, which allows remote
attackers to forge a PKCS signature that apapears to be
signed by that RSA key and prevents gnutls from correctly
verifying the certificate.
This bug has been tracked by the Mitre CVE ID CVE-2006-4790.
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch 11228");
script_end_attributes();

script_cve_id("CVE-2006-4790");
script_summary(english: "Check for the security advisory #11228");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gnutls-1.0.8-26.10", release:"SUSE9", cpu: "i586") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gnutls-devel-1.0.8-26.10", release:"SUSE9", cpu: "i586") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

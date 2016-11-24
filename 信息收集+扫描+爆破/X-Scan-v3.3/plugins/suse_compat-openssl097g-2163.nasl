
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29405);
 script_version ("$Revision: 1.7 $");
 script_name(english: "SuSE Security Update:  Security update for compat-openssl097g (compat-openssl097g-2163)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch compat-openssl097g-2163");
 script_set_attribute(attribute: "description", value: "A buffer overflow condition within the
SSL_get_shared_ciphers() function and a DoS condition known
as 'parasitic public keys' have been fixed. The later
problem allowed attackers to trick the OpenSSL engine to
spend an extraordinary amount of time to process public
keys. The following CAN numbers have been assigned:
CVE-2006-2937, CVE-2006-2940, CVE-2006-3738, CVE-2006-4339
and CVE-2006-4343.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch compat-openssl097g-2163");
script_end_attributes();

script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4339", "CVE-2006-4343");
script_summary(english: "Check for the compat-openssl097g-2163 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"compat-openssl097g-0.9.7g-13.5", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"compat-openssl097g-0.9.7g-13.5", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

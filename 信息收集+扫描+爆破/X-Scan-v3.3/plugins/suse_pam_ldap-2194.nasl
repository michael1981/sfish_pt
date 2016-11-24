
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27381);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  PasswordPolicyResponse control was handled incorrectly (pam_ldap-2194)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch pam_ldap-2194");
 script_set_attribute(attribute: "description", value: "pam_ldap did not return an error conditions correctly when
an LDAP directory server responded with a
PasswordPolicyResponse control response, which caused the
pam_authenticate function to return a success code even if
authentication has failed. (CVE-2006-5170)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch pam_ldap-2194");
script_end_attributes();

script_cve_id("CVE-2006-5170");
script_summary(english: "Check for the pam_ldap-2194 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"pam_ldap-180-13.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"pam_ldap-32bit-180-13.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"pam_ldap-64bit-180-13.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

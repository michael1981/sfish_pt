
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27352);
 script_version ("$Revision: 1.11 $");
 script_name(english: "SuSE Security Update:  mozilla-nss: Fixed RSA signature verification problem (mozilla-nss-2071)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch mozilla-nss-2071");
 script_set_attribute(attribute: "description", value: "A security problem in the SSL handling of the NSS libraries
was found:

If an RSA key with exponent 3 is used it may be possible to
forge a PKCS verify the certificate if they are not
checking for excess data in the RSA exponentiation result
of the signature.

This bug is tracked by the Mitre CVE ID CVE-2006-4340 and
CVE-2006-4341.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch mozilla-nss-2071");
script_end_attributes();

 script_cve_id("CVE-2006-4340");
script_summary(english: "Check for the mozilla-nss-2071 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"mozilla-nss-3.11-21.7", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-nss-32bit-3.11-21.7", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-nss-64bit-3.11-21.7", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-3.11-21.7", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

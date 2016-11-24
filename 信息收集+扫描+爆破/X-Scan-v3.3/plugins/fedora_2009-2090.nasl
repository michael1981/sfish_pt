
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2090
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36796);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-2090: perl-Crypt-OpenSSL-DSA");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2090 (perl-Crypt-OpenSSL-DSA)");
 script_set_attribute(attribute: "description", value: "Crypt::OpenSSL::DSA - Digital Signature Algorithm using OpenSSL

-
Update Information:

Fixes CVE-2009-0129: The Crypto::OpenSSL::DSA module now croaks upon error
rather than returning a -1 to ensure programmers are not caught by surprise
which only checking for non-zero results.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0129");
script_summary(english: "Check for the version of the perl-Crypt-OpenSSL-DSA package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"perl-Crypt-OpenSSL-DSA-0.13-12.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

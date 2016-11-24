
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-0419
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37826);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 10 2009-0419: tqsllib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-0419 (tqsllib)");
 script_set_attribute(attribute: "description", value: "The TrustedQSL library is used for generating digitally signed
QSO records (records of Amateur Radio contacts). This package
contains the library and configuration files needed to run
TrustedQSL applications.

-
Update Information:

The TrustedQSL library incorrectly checked the result after  calling the
EVP_VerifyFinal function, allowing a malformed signature to be treated as a goo
d
signature rather than as an error. Package includes a patch to fix
EVP_VerifyFinal result check.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5077");
script_summary(english: "Check for the version of the tqsllib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"tqsllib-2.0-5.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40522);
 script_version("$Revision: 1.4 $");
 script_name(english: "MDVSA-2009:197-2: nss");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:197-2 (nss).");
 script_set_attribute(attribute: "description", value: "Security issues in nss prior to 3.12.3 could lead to a
man-in-the-middle attack via a spoofed X.509 certificate
(CVE-2009-2408) and md2 algorithm flaws (CVE-2009-2409), and also
cause a denial-of-service and possible code execution via a long
domain name in X.509 certificate (CVE-2009-2404).
This update provides the latest versions of NSS and NSPR libraries
which are not vulnerable to those attacks.
Update:
This update also provides fixed packages for Mandriva Linux 2008.1
and fixes mozilla-thunderbird error messages.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:197-2");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2409");
script_summary(english: "Check for the version of the nss package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libnss3-3.12.3.1-0.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnss-devel-3.12.3.1-0.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnss-static-devel-3.12.3.1-0.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nss-3.12.3.1-0.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"nss-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2009-2404", value:TRUE);
 set_kb_item(name:"CVE-2009-2408", value:TRUE);
 set_kb_item(name:"CVE-2009-2409", value:TRUE);
}
exit(0, "Host is not affected");

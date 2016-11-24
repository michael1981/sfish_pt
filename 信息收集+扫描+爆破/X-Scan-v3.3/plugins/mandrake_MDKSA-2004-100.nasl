
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14794);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2004:100: mpg123");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:100 (mpg123).");
 script_set_attribute(attribute: "description", value: "A vulnerability in mpg123 was discovered by Davide Del Vecchio where
certain malicious mpg3/2 files would cause mpg123 to fail header
checks, which could in turn allow arbitrary code to be executed with
the privileges of the user running mpg123 (CVE-2004-0805).
As well, an older vulnerability in mpg123, where a response from a
remote HTTP server could overflow a buffer allocated on the heap, is
also fixed in these packages. This vulnerability could also
potentially permit the execution of arbitray code with the privileges
of the user running mpg123 (CVE-2003-0865).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:100");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0865", "CVE-2004-0805");
script_summary(english: "Check for the version of the mpg123 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mpg123-0.59r-21.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mpg123-0.59r-21.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mpg123-", release:"MDK10.0")
 || rpm_exists(rpm:"mpg123-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0865", value:TRUE);
 set_kb_item(name:"CVE-2004-0805", value:TRUE);
}
exit(0, "Host is not affected");

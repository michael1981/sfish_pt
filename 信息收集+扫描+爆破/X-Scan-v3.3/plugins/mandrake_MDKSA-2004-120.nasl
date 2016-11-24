
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15600);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2004:120: mpg123");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:120 (mpg123).");
 script_set_attribute(attribute: "description", value: "Carlos Barros discovered two buffer overflow vulnerabilities in mpg123;
the first in the getauthfromURL() function and the second in the
http_open() function. These vulnerabilities could be exploited to
possibly execute arbitrary code with the privileges of the user running
mpg123.
The provided packages are patched to fix these issues, as well
additional boundary checks that were lacking have been included (thanks
to the Gentoo Linux Sound Team for these additional fixes).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:120");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0982");
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

if ( rpm_check( reference:"mpg123-0.59r-22.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mpg123-0.59r-22.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mpg123-", release:"MDK10.0")
 || rpm_exists(rpm:"mpg123-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-0982", value:TRUE);
}
exit(0, "Host is not affected");

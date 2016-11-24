
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21617);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:093: dia");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:093 (dia).");
 script_set_attribute(attribute: "description", value: "A format string vulnerability in Dia allows user-complicit
attackers to cause a denial of service (crash) and possibly execute
arbitrary code by triggering errors or warnings, as demonstrated via
format string specifiers in a .bmp filename. NOTE: the original
exploit was demonstrated through a command line argument, but there
are other mechanisms inputs that are automatically process by Dia,
such as a crafted .dia file. (CVE-2006-2480)
Multiple unspecified format string vulnerabilities in Dia have
unspecified impact and attack vectors, a different set of issues
than CVE-2006-2480. (CVE-2006-2453)
Packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:093");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-2453", "CVE-2006-2480");
script_summary(english: "Check for the version of the dia package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dia-0.94-6.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"dia-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2453", value:TRUE);
 set_kb_item(name:"CVE-2006-2480", value:TRUE);
}
exit(0, "Host is not affected");

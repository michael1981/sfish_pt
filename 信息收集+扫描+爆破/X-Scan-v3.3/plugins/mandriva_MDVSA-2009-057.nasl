
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38051);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:057: valgrind");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:057 (valgrind).");
 script_set_attribute(attribute: "description", value: "A vulnerability has been identified and corrected in valgrind:
Untrusted search path vulnerability in valgrind before 3.4.0
allows local users to execute arbitrary programs via a Trojan horse
.valgrindrc file in the current working directory, as demonstrated
using a malicious --db-command options. NOTE: the severity of this
issue has been disputed, but CVE is including this issue because
execution of a program from an untrusted directory is a common
scenario. (CVE-2008-4865)
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:057");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-4865");
script_summary(english: "Check for the version of the valgrind package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"valgrind-3.2.3-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"valgrind-3.3.0-3.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"valgrind-3.3.1-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"valgrind-", release:"MDK2008.0")
 || rpm_exists(rpm:"valgrind-", release:"MDK2008.1")
 || rpm_exists(rpm:"valgrind-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-4865", value:TRUE);
}
exit(0, "Host is not affected");

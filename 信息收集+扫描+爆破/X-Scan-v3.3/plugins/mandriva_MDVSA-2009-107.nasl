
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38707);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:107: acpid");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:107 (acpid).");
 script_set_attribute(attribute: "description", value: "The daemon in acpid before 1.0.10 allows remote attackers to cause a
denial of service (CPU consumption and connectivity loss) by opening
a large number of UNIX sockets without closing them, which triggers
an infinite loop (CVE-2009-0798).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:107");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-0798");
script_summary(english: "Check for the version of the acpid package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"acpid-1.0.6-4.1mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acpid-1.0.6-6.1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acpid-1.0.8-1.1mnb2", release:"MDK2009.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"acpid-", release:"MDK2008.1")
 || rpm_exists(rpm:"acpid-", release:"MDK2009.0")
 || rpm_exists(rpm:"acpid-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-0798", value:TRUE);
}
exit(0, "Host is not affected");

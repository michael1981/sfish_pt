
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13950);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2002:047: util-linux");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:047 (util-linux).");
 script_set_attribute(attribute: "description", value: "Michal Zalewski found a vulnerability in the util-linux package with
the chfn utility. This utility allows users to modify some information
in the /etc/passwd file, and is installed setuid root. Using a
carefully crafted attack sequence, an attacker can exploit a complex
file locking and modification race that would allow them to make
changes to the /etc/passwd file. To successfully exploit this
vulnerability and obtain privilege escalation, there is a need for some
administrator interaction, and the password file must over over 4kb in
size; the attacker's entry cannot be in the last 4kb of the file.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:047");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-0638");
script_summary(english: "Check for the version of the util-linux package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"util-linux-2.10o-6.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.10o-6.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.10s-3.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.11h-3.5mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"losetup-2.11n-4.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mount-2.11n-4.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.11n-4.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"util-linux-", release:"MDK7.1")
 || rpm_exists(rpm:"util-linux-", release:"MDK7.2")
 || rpm_exists(rpm:"util-linux-", release:"MDK8.0")
 || rpm_exists(rpm:"util-linux-", release:"MDK8.1")
 || rpm_exists(rpm:"util-linux-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0638", value:TRUE);
}
exit(0, "Host is not affected");

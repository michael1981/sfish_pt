
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(23891);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:142: heartbeat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:142 (heartbeat).");
 script_set_attribute(attribute: "description", value: "Two vulnerabilities in heartbeat prior to 2.0.6 was discovered by Yan
Rong Ge. The first is that heartbeat would set insecure permissions in
an shmget call for shared memory, allowing a local attacker to cause an
unspecified denial of service via unknown vectors (CVE-2006-3815).
The second is a remote vulnerability that could allow allow the master
control process to read invalid memory due to a specially crafted
heartbeat message and die of a SEGV, all prior to any authentication
(CVE-2006-3121).
Updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:142");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-3121", "CVE-2006-3815");
script_summary(english: "Check for the version of the heartbeat package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"heartbeat-1.2.3-5.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"heartbeat-ldirectord-1.2.3-5.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"heartbeat-pils-1.2.3-5.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"heartbeat-stonith-1.2.3-5.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libheartbeat0-1.2.3-5.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libheartbeat0-devel-1.2.3-5.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libheartbeat-pils0-1.2.3-5.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libheartbeat-pils0-devel-1.2.3-5.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libheartbeat-stonith0-1.2.3-5.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libheartbeat-stonith0-devel-1.2.3-5.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"heartbeat-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-3121", value:TRUE);
 set_kb_item(name:"CVE-2006-3815", value:TRUE);
}
exit(0, "Host is not affected");

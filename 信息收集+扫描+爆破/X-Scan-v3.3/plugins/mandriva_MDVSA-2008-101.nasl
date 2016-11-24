
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37563);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:101: rdesktop");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:101 (rdesktop).");
 script_set_attribute(attribute: "description", value: "Several vulnerabilities were discovered in rdesktop, a Remote Desktop
Protocol client.
An integer underflow vulnerability allowed attackers to cause a
denial of service (crash) and possibly execute arbitrary code with
the privileges of the logged-in user (CVE-2008-1801).
A buffer overflow vulnerability allowed attackers to execute arbitrary
code with the privileges of the logged-in user (CVE-2008-1802).
An integer signedness vulnerability allowed attackers to
execute arbitrary code with the privileges of the logged-in user
(CVE-2008-1803).
In order for these vulnerabilities to be exploited, an attacker must
persuade a targeted user to connect to a malicious RDP server.
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:101");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-1801", "CVE-2008-1802", "CVE-2008-1803");
script_summary(english: "Check for the version of the rdesktop package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"rdesktop-1.5.0-1.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rdesktop-1.5.0-3.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rdesktop-1.5.0-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"rdesktop-", release:"MDK2007.1")
 || rpm_exists(rpm:"rdesktop-", release:"MDK2008.0")
 || rpm_exists(rpm:"rdesktop-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-1801", value:TRUE);
 set_kb_item(name:"CVE-2008-1802", value:TRUE);
 set_kb_item(name:"CVE-2008-1803", value:TRUE);
}
exit(0, "Host is not affected");

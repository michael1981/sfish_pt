
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38165);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDVSA-2009:097: clamav");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:097 (clamav).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities has been found and corrected in clamav:
Unspecified vulnerability in ClamAV before 0.95 allows remote
attackers to bypass detection of malware via a modified RAR archive
(CVE-2009-1241).
libclamav/pe.c in ClamAV before 0.95 allows remote attackers to cause
a denial of service (crash) via a crafted EXE file that triggers a
divide-by-zero error (CVE-2008-6680).
libclamav/untar.c in ClamAV before 0.95 allows remote attackers to
cause a denial of service (infinite loop) via a crafted file that
causes (1) clamd and (2) clamscan to hang (CVE-2009-1270).
The CLI_ISCONTAINED macro in libclamav/others.h in ClamAV before 0.95.1
allows remote attackers to cause a denial of service (application
crash) via a malformed file with UPack encoding (CVE-2009-1371).
Stack-based buffer overflow in the cli_url_canon function in
libclamav/phishcheck.c in ClamAV before 0.95.1 allows remote attackers
to cause a denial of service (application crash) and possibly execute
arbitrary code via a crafted URL (CVE-2009-1372).
Important notice about this upgrade: clamav-0.95+ bundles support
for RAR v3 in libclamav which is a license violation as the RAR v3
license and the GPL license is not compatible. As a consequence to
this Mandriva has been forced to remove the RAR v3 code.
This update provides clamav 0.95.1, which is not vulnerable to
these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:097");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-6680", "CVE-2009-1241", "CVE-2009-1270", "CVE-2009-1371", "CVE-2009-1372");
script_summary(english: "Check for the version of the clamav package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"clamav-0.95.1-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.95.1-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamav-milter-0.95.1-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamd-0.95.1-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libclamav6-0.95.1-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libclamav-devel-0.95.1-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamav-0.95.1-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.95.1-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamav-milter-0.95.1-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamd-0.95.1-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libclamav6-0.95.1-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libclamav-devel-0.95.1-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"clamav-", release:"MDK2008.1")
 || rpm_exists(rpm:"clamav-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-6680", value:TRUE);
 set_kb_item(name:"CVE-2009-1241", value:TRUE);
 set_kb_item(name:"CVE-2009-1270", value:TRUE);
 set_kb_item(name:"CVE-2009-1371", value:TRUE);
 set_kb_item(name:"CVE-2009-1372", value:TRUE);
}
exit(0, "Host is not affected");

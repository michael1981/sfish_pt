
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20128);
 script_version ("$Revision: 1.4 $");
 script_name(english: "MDKSA-2005:204: wget");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:204 (wget).");
 script_set_attribute(attribute: "description", value: "Hugo Vazquez Carames discovered a race condition when writing output
files in wget. After wget determined the output file name, but before
the file was actually opened, a local attacker with write permissions
to the download directory could create a symbolic link with the name
of the output file. This could be exploited to overwrite arbitrary
files with the permissions of the user invoking wget. The time window
of opportunity for the attacker is determined solely by the delay of
the first received data packet.
The updated packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:204");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-2014");
script_summary(english: "Check for the version of the wget package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"wget-1.9.1-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wget-1.9.1-5.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"wget-", release:"MDK10.1")
 || rpm_exists(rpm:"wget-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2004-2014", value:TRUE);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14077);
 script_version ("$Revision: 1.8 $");
 script_name(english: "MDKSA-2003:095-1: proftpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:095-1 (proftpd).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered by X-Force Research at ISS in ProFTPD's
handling of ASCII translation. An attacker, by downloading a carefully
crafted file, can remotely exploit this bug to create a root shell.
The ProFTPD team encourages all users to upgrade to version 1.2.7 or
higher. The problematic code first appeared in ProFTPD 1.2.7rc1, and
the provided packages are all patched by the ProFTPD team to protect
against this vulnerability.
Update:
The previous update had a bug where the new packages would terminate
with a SIGNAL 11 when the command 'NLST -alL' was performed in
certain cases, such as if the size of the output of the command was
greater than 1024 bytes.
These updated packages have a fix applied to prevent this crash.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:095-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0831");
script_summary(english: "Check for the version of the proftpd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"proftpd-1.2.8-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-anonymous-1.2.8-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-1.2.8-5.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-anonymous-1.2.8-5.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"proftpd-", release:"MDK9.1")
 || rpm_exists(rpm:"proftpd-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0831", value:TRUE);
}
exit(0, "Host is not affected");

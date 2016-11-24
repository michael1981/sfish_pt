
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15915);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2004:142: gzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:142 (gzip).");
 script_set_attribute(attribute: "description", value: "The Trustix developers found some insecure temporary file creation
problems in the zdiff, znew, and gzeze supplemental scripts in the
gzip package. These flaws could allow local users to overwrite files
via a symlink attack.
A similar problem was fixed last year (CVE-2003-0367) in which this
same problem was found in znew. At that time, Mandrakesoft also used
mktemp to correct the problems in gzexe. This update uses mktemp to
handle temporary files in the zdiff script.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:142");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0970");
script_summary(english: "Check for the version of the gzip package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gzip-1.2.4a-13.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-13.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-13.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gzip-", release:"MDK10.0")
 || rpm_exists(rpm:"gzip-", release:"MDK10.1")
 || rpm_exists(rpm:"gzip-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0970", value:TRUE);
}
exit(0, "Host is not affected");

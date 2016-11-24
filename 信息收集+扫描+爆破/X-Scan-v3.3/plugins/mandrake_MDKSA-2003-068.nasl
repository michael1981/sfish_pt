
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14051);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:068: gzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:068 (gzip).");
 script_set_attribute(attribute: "description", value: "A vulnerability exists in znew, a script included with gzip, that
would create temporary files without taking precautions to avoid a
symlink attack. Patches have been applied to make use of mktemp to
generate unique filenames, and properly make use of noclobber in the
script. Likewise, a fix for gzexe which had been applied previously
was incomplete. It has been fixed to make full use of mktemp
everywhere a temporary file is created.
The znew problem was initially reported by Michal Zalewski and was
again reported more recently to Debian by Paul Szabo.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:068");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-1999-1332", "CVE-2003-0367");
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

if ( rpm_check( reference:"gzip-1.2.4a-11.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-11.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-11.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gzip-", release:"MDK8.2")
 || rpm_exists(rpm:"gzip-", release:"MDK9.0")
 || rpm_exists(rpm:"gzip-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-1999-1332", value:TRUE);
 set_kb_item(name:"CVE-2003-0367", value:TRUE);
}
exit(0, "Host is not affected");

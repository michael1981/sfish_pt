
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16360);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:031: perl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:031 (perl).");
 script_set_attribute(attribute: "description", value: "Jeroen van Wolffelaar discovered that the rmtree() function in the perl
File::Path module would remove directories in an insecure manner which
could lead to the removal of arbitrary files and directories via a
symlink attack (CVE-2004-0452).
Trustix developers discovered several insecure uses of temporary files
in many modules which could allow a local attacker to overwrite files
via symlink attacks (CVE-2004-0976).
'KF' discovered two vulnerabilities involving setuid-enabled perl
scripts. By setting the PERLIO_DEBUG environment variable and calling
an arbitrary setuid-root perl script, an attacker could overwrite
arbitrary files with perl debug messages (CVE-2005-0155). As well,
calling a setuid-root perl script with a very long path would cause a
buffer overflow if PERLIO_DEBUG was set, which could be exploited to
execute arbitrary files with root privileges (CVE-2005-0156).
The provided packages have been patched to resolve these problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:031");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0452", "CVE-2004-0976", "CVE-2005-0155", "CVE-2005-0156");
script_summary(english: "Check for the version of the perl package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"perl-5.8.3-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-base-5.8.3-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-devel-5.8.3-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-doc-5.8.3-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-5.8.5-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-base-5.8.5-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-devel-5.8.5-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-doc-5.8.5-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-5.8.1-0.RC4.3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-base-5.8.1-0.RC4.3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-devel-5.8.1-0.RC4.3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-doc-5.8.1-0.RC4.3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"perl-", release:"MDK10.0")
 || rpm_exists(rpm:"perl-", release:"MDK10.1")
 || rpm_exists(rpm:"perl-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0452", value:TRUE);
 set_kb_item(name:"CVE-2004-0976", value:TRUE);
 set_kb_item(name:"CVE-2005-0155", value:TRUE);
 set_kb_item(name:"CVE-2005-0156", value:TRUE);
}
exit(0, "Host is not affected");

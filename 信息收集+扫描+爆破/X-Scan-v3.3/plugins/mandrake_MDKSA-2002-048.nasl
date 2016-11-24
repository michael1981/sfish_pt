
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13951);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2002:048: mod_ssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:048 (mod_ssl).");
 script_set_attribute(attribute: "description", value: "Frank Denis discovered an off-by-one error in mod_ssl dealing with the
handling of older configuration directorives (the rewrite_command
hook). A malicious user could use a specially-crafted .htaccess file
to execute arbitrary commands as the apache user or execute a DoS
against the apache child processes.
This vulnerability is fixed in mod_ssl 2.8.10; patches have been
applied to correct this problem in these packages.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:048");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-0653");
script_summary(english: "Check for the version of the mod_ssl package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mod_ssl-2.8.5-3.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.5-3.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.5-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.5-3.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.7-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mod_ssl-", release:"MDK7.1")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK7.2")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK8.0")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK8.1")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0653", value:TRUE);
}
exit(0, "Host is not affected");

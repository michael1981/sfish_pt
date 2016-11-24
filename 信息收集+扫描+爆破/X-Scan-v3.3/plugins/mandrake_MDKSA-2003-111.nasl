
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14093);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:111: rsync");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:111 (rsync).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered in all versions of rsync prior to 2.5.7
that was recently used in conjunction with the Linux kernel do_brk()
vulnerability to compromise a public rsync server.
This heap overflow vulnerability, by itself, cannot yield root access,
however it does allow arbitrary code execution on the host running
rsync as a server. Also note that this only affects hosts running
rsync in server mode (listening on port 873, typically under xinetd).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:111");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0962");
script_summary(english: "Check for the version of the rsync package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"rsync-2.5.5-5.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-0.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"rsync-", release:"MDK9.0")
 || rpm_exists(rpm:"rsync-", release:"MDK9.1")
 || rpm_exists(rpm:"rsync-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0962", value:TRUE);
}
exit(0, "Host is not affected");

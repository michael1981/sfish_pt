
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14060);
 script_version ("$Revision: 1.10 $");
 script_name(english: "MDKSA-2003:077: phpgroupware");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:077 (phpgroupware).");
 script_set_attribute(attribute: "description", value: "Several vulnerabilities were discovered in all versions of phpgroupware
prior to 0.9.14.006. This latest version fixes an exploitable
condition in all versions that can be exploited remotely without
authentication and can lead to arbitrary code execution on the web
server. This vulnerability is being actively exploited.
Version 0.9.14.005 fixed several other vulnerabilities including
cross-site scripting issues that can be exploited to obtain
sensitive information such as authentication cookies.
This update provides the latest stable version of phpgroupware and all
users are encouraged to update immediately. In addition, you should
also secure your installation by including the following in your Apache
configuration files:
Order allow,deny
Deny from all
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:077");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

 script_cve_id("CVE-2003-0504");
script_summary(english: "Check for the version of the phpgroupware package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"phpgroupware-0.9.14.006-0.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"phpgroupware-0.9.14.006-0.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"phpgroupware-0.9.14.006-0.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"phpgroupware-", release:"MDK8.2")
 || rpm_exists(rpm:"phpgroupware-", release:"MDK9.0")
 || rpm_exists(rpm:"phpgroupware-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0504", value:TRUE);
 set_kb_item(name:"CVE-2003-0582", value:TRUE);
}
exit(0, "Host is not affected");

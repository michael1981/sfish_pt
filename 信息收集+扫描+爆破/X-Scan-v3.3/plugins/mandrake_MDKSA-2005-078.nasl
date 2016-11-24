
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18171);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:078: squid");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:078 (squid).");
 script_set_attribute(attribute: "description", value: "Squid 2.5, when processing the configuration file, parses empty Access
Control Lists (ACLs), including proxy_auth ACLs without defined auth
schemes, in a way that effectively removes arguments, which could allow
remote attackers to bypass intended ACLs if the administrator ignores
the parser warnings. (CVE-2005-0194)
Race condition in Squid 2.5.STABLE7 to 2.5.STABLE9, when using the Netscape
Set-Cookie recommendations for handling cookies in caches, may cause
Set-Cookie headers to be sent to other users, which allows attackers to
steal the related cookies. (CVE-2005-0626)
Squid 2.5.STABLE7 and earlier allows remote attackers to cause a denial
of service (segmentation fault) by aborting the connection during a (1)
PUT or (2) POST request, which causes Squid to access previosuly freed
memory. (CVE-2005-0718)
A bug in the way Squid processes errors in the access control list was
also found. It is possible that an error in the access control list
could give users more access than intended. (CVE-2005-1345)
In addition, due to subtle bugs in the previous backported updates of
squid (Bugzilla #14209), all the squid-2.5 versions have been updated to
squid-2.5.STABLE9 with all the STABLE9 patches from the squid developers.
The updated packages are patched to fix these problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:078");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0194", "CVE-2005-0626", "CVE-2005-0718", "CVE-2005-1345");
script_summary(english: "Check for the version of the squid package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"squid-2.5.STABLE9-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE6-2.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE9-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE9-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"squid-", release:"MDK10.0")
 || rpm_exists(rpm:"squid-", release:"MDK10.1")
 || rpm_exists(rpm:"squid-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-0194", value:TRUE);
 set_kb_item(name:"CVE-2005-0626", value:TRUE);
 set_kb_item(name:"CVE-2005-0718", value:TRUE);
 set_kb_item(name:"CVE-2005-1345", value:TRUE);
}
exit(0, "Host is not affected");

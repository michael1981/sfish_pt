
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36821);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:236-1: vim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:236-1 (vim).");
 script_set_attribute(attribute: "description", value: "Several vulnerabilities were found in the vim editor:
A number of input sanitization flaws were found in various vim
system functions. If a user were to open a specially crafted file,
it would be possible to execute arbitrary code as the user running vim
(CVE-2008-2712).
Ulf H?rnhammar of Secunia Research found a format string flaw in
vim's help tags processor. If a user were tricked into executing the
helptags command on malicious data, it could result in the execution
of arbitrary code as the user running vim (CVE-2008-2953).
A flaw was found in how tar.vim handled TAR archive browsing. If a
user were to open a special TAR archive using the plugin, it could
result in the execution of arbitrary code as the user running vim
(CVE-2008-3074).
A flaw was found in how zip.vim handled ZIP archive browsing. If a
user were to open a special ZIP archive using the plugin, it could
result in the execution of arbitrary code as the user running vim
(CVE-2008-3075).
A number of security flaws were found in netrw.vim, the vim plugin
that provides the ability to read and write files over the network.
If a user opened a specially crafted file or directory with the netrw
plugin, it could result in the execution of arbitrary code as the
user running vim (CVE-2008-3076).
A number of input validation flaws were found in vim's keyword and
tag handling. If vim looked up a document's maliciously crafted
tag or keyword, it was possible to execute arbitary code as the user
running vim (CVE-2008-4101).
A vulnerability was found in certain versions of netrw.vim where it
would send FTP credentials stored for an FTP session to subsequent
FTP sessions to servers on different hosts, exposing FTP credentials
to remote hosts (CVE-2008-4677).
This update provides vim 7.2 (patchlevel 65) which corrects all of
these issues and introduces a number of new features and bug fixes.
Update:
The previous vim update incorrectly introduced a requirement on
libruby and also conflicted with a file from the git-core package
(in contribs). These issues have been corrected with these updated
packages.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:236-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-2712", "CVE-2008-2953", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076", "CVE-2008-4101", "CVE-2008-4677");
script_summary(english: "Check for the version of the vim package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"vim-common-7.2.065-9.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-7.2.065-9.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-7.2.065-9.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-X11-7.2.065-9.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-common-7.2.065-9.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-7.2.065-9.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-7.2.065-9.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-X11-7.2.065-9.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-common-7.2.065-9.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-7.2.065-9.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-7.2.065-9.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vim-X11-7.2.065-9.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"vim-", release:"MDK2008.0")
 || rpm_exists(rpm:"vim-", release:"MDK2008.1")
 || rpm_exists(rpm:"vim-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-2712", value:TRUE);
 set_kb_item(name:"CVE-2008-2953", value:TRUE);
 set_kb_item(name:"CVE-2008-3074", value:TRUE);
 set_kb_item(name:"CVE-2008-3075", value:TRUE);
 set_kb_item(name:"CVE-2008-3076", value:TRUE);
 set_kb_item(name:"CVE-2008-4101", value:TRUE);
 set_kb_item(name:"CVE-2008-4677", value:TRUE);
}
exit(0, "Host is not affected");

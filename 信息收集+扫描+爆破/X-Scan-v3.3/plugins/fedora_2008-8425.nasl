
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-8425
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34308);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-8425: chmsee");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-8425 (chmsee)");
 script_set_attribute(attribute: "description", value: "A gtk2 chm document viewer.

It uses chmlib to extract files. It uses gecko to display pages. It supports
displaying multilingual pages due to gecko. It features bookmarks and tabs.
The tabs could be used to jump inside the chm file conveniently. Its UI is
clean and handy, also is well localized. It is actively developed and
maintained. The author of chmsee is Jungle Ji and several other great people.

Hint
* Unlike other chm viewers, chmsee extracts files from chm file, and then read
and display them. The extracted files could be found in $HOME/.chmsee/bookshelf
directory. You can clean those files at any time and there is a special config
option for that.
* The bookmark is related to each file so not all bookmarks will be loaded,
only current file's.
* Try to remove $HOME/.chmsee if you encounter any problem after an upgrade.

-
Update Information:

Mozilla Firefox is an open source Web browser.    Several flaws were found in
the processing of malformed web content. A web page containing malicious conten
t
could cause Firefox to crash or, potentially, execute arbitrary code as the use
r
running Firefox. (CVE-2008-4058, CVE-2008-4060, CVE-2008-4061, CVE-2008-4062,
CVE-2008-4063, CVE-2008-4064)    Several flaws were found in the way malformed
web content was displayed. A web page containing specially crafted content coul
d
potentially trick a Firefox user into surrendering sensitive information.
(CVE-2008-4067, CVE-2008-4068)    A flaw was found in the way Firefox handles
mouse click events. A web page containing specially crafted JavaScript code
could move the content window while a mouse-button was pressed, causing any ite
m
under the pointer to be dragged. This could, potentially, cause the user to
perform an unsafe drag-and-drop action. (CVE-2008-3837)    A flaw was found in
Firefox that caused certain characters to be stripped from JavaScript code. Thi
s
flaw could allow malicious JavaScript to bypass or evade script filters.
(CVE-2008-4065)    For technical details regarding these flaws, please see the
Mozilla security advisories for Firefox 3.0.2.[1]    All Firefox users should
upgrade to these updated packages, which contain patches that correct these
issues.    [1] [9]http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.2
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3837", "CVE-2008-4062", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4068");
script_summary(english: "Check for the version of the chmsee package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"chmsee-1.0.1-5.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

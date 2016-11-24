
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3249
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32040);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-3249: chmsee");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3249 (chmsee)");
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

Mozilla Firefox is an open source Web browser.    A flaw was found in the
processing of malformed JavaScript content. A web page containing such maliciou
s
content could cause Firefox to crash or, potentially, execute arbitrary code as
the user running Firefox. (CVE-2008-1380)    All Firefox users should upgrade t
o
these updated packages, which contain backported patches that correct these
issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1380");
script_summary(english: "Check for the version of the chmsee package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"chmsee-1.0.0-2.30.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

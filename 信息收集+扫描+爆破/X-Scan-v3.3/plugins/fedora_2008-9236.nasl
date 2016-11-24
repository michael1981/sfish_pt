
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-9236
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34674);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-9236: ed");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-9236 (ed)");
 script_set_attribute(attribute: "description", value: "Ed is a line-oriented text editor, used to create, display, and modify
text files (both interactively and via shell scripts).  For most
purposes, ed has been replaced in normal usage by full-screen editors
(emacs and vi, for example).

Ed was the original UNIX editor, and may be used by some programs.  In
general, however, you probably don't need to install it and you probably
won't use it.

-
Update Information:

ed is a line-oriented text editor, used to create, display, and modify  text
files (both interactively and via shell scripts).    A heap-based buffer
overflow was discovered in the way ed, the GNU line  editor, processed long fil
e
names. An attacker could create a file with a  specially-crafted name that coul
d
possibly execute an arbitrary code when  opened in the ed editor.
(CVE-2008-3916)    Users of ed should upgrade to this updated package, which
contains  a backported patch to resolve this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3916");
script_summary(english: "Check for the version of the ed package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ed-1.1-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

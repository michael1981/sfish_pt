
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2981
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31821);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-2981: comix");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2981 (comix)");
 script_set_attribute(attribute: "description", value: "Comix is a user-friendly, customizable image viewer.
It is specifically designed to handle comic books, but
also serves as a generic viewer. It reads images in ZIP,
RAR or tar archives (also gzip or bzip2 compressed) as
well as plain image files. It is written in Python and
uses GTK+ through the PyGTK bindings.

-
Update Information:

Several security flaws are reported against comix 3.6.4.    One issue is that
comix uses os.popen() to execute external commands without handling filenames
properly. This may allow malicios users to execute arbitrary commands by openin
g
some files with crafted names. This issue is now identified as CVE-2008-1568.
Another issue is that comix creates a directory under /tmp with the name easily
predictable by any users. This will cause DOS attach for multiuser system.
This new package will fix these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1568");
script_summary(english: "Check for the version of the comix package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"comix-3.6.4-6.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

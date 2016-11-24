
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8997
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40866);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-8997: xemacs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8997 (xemacs)");
 script_set_attribute(attribute: "description", value: "XEmacs is a highly customizable open source text editor and
application development system.  It is protected under the GNU General
Public License and related to other versions of Emacs, in particular
GNU Emacs.  Its emphasis is on modern graphical user interface support
and an open software development model, similar to Linux.

This package contains XEmacs built for X Windows with MULE support.

-
Update Information:

This update fixes multiple buffer overflows when reading large image files, or
maliciously created image files whose headers misrepresent the actual image
size.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-2688");
script_summary(english: "Check for the version of the xemacs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xemacs-21.5.28-10.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

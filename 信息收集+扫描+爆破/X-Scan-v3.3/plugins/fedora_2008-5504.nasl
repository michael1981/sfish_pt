
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-5504
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33237);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-5504: xemacs-packages-extra");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-5504 (xemacs-packages-extra)");
 script_set_attribute(attribute: "description", value: "XEmacs is a highly customizable open source text editor and
application development system.  It is protected under the GNU General
Public License and related to other versions of Emacs, in particular
GNU Emacs.  Its emphasis is on modern graphical user interface support
and an open software development model, similar to Linux.

The XEmacs packages collection contains a large collection of useful
lisp packages for XEmacs including mailreaders, programming modes and
utilities, and packages related to using XEmacs in multi-lingual
environments.

-
Update Information:


Update information :

* Wed Jun 18 2008 Ville SkyttÃ¤ <ville.skytta at iki.fi> - 20070427-2  - Apply
upstream security fix for CVE-2008-2142 (#446069).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2142");
script_summary(english: "Check for the version of the xemacs-packages-extra package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xemacs-packages-extra-20070427-2.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

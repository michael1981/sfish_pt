
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-1187
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37553);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-1187: gedit");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-1187 (gedit)");
 script_set_attribute(attribute: "description", value: "gEdit is a small but powerful text editor designed specifically for
the GNOME GUI desktop.  gEdit includes a plug-in API (which supports
extensibility while keeping the core binary small), support for
editing multiple documents using notebook tabs, and standard text
editor functions.

You'll need to have GNOME and GTK+ installed to use gEdit.

-
Update Information:

Untrusted search path vulnerability in gedit's Python module allows local users
to execute arbitrary code via a Trojan horse Python file in the current working
directory, related to an erroneous setting of sys.path by the PySys_SetArgv
function.    References:  [9]http://bugzilla.gnome.org/show_bug.cgi?id=569214
[10]http://www.nabble.com/Bug-484305%3A-bicyclerepair%3A-bike.vim-imports-untru
sted-
python-files-from-cwd-td18848099.html     The latest stable upstream release of
gedit.  From the release announcement:    New Features and Fixes
======================  - Backport some bugfixes from the developement version
New and updated translations  ============================  - Alexander Shopov
(bg)  - Priit Laes (et)  - Shankar Prasad (kn)
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the gedit package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gedit-2.24.3-3.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

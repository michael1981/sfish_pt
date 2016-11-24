
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-1213
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36882);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-1213: gstreamer-plugins-good");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-1213 (gstreamer-plugins-good)");
 script_set_attribute(attribute: "description", value: "GStreamer is a streaming media framework, based on graphs of filters which
operate on media data. Applications using this library can do anything
from real-time sound processing to playing videos, and just about anything
else media-related.  Its plugin-based architecture means that new data
types or processing capabilities can be added simply by installing new
plug-ins.

GStreamer Good Plug-ins is a collection of well-supported plug-ins of
good quality and under the LGPL license.

-
ChangeLog:


Update information :

* Mon Jan 26 2009 - Bastien Nocera <bnocera redhat com> - 0.10.13-1
- Update to 0.10.13
- Update libv4l patch
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0386", "CVE-2009-0387");
script_summary(english: "Check for the version of the gstreamer-plugins-good package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gstreamer-plugins-good-0.10.13-1.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1594
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27723);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1594: kdegraphics");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1594 (kdegraphics)");
 script_set_attribute(attribute: "description", value: "Graphics applications for the K Desktop Environment, including
* kamera (digital camera support)
* kcoloredit (palette editor and color chooser)
* kdvi (displays TeX .dvi files)
* kghostview (displays postscript files)
* kiconedit (icon editor)
* kooka (scanner application)
* kpdf (displays PDF files)
* kruler (screen ruler and color measurement tool)
* ksnapshot (screen capture utility)
* kview (image viewer for GIF, JPEG, TIFF, etc.)

-
Update Information:

This is an update to address a vulnerability in kpdf, one that can cause a stac
k based buffer overflow.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3387");
script_summary(english: "Check for the version of the kdegraphics package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kdegraphics-3.5.7-2.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

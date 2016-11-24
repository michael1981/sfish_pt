
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2989
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(28154);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-2989: hugin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2989 (hugin)");
 script_set_attribute(attribute: "description", value: "hugin can be used to stitch multiple images together. The resulting image can
span 360 degrees. Another common use is the creation of very high resolution
pictures by combining multiple images.  It uses the Panorama Tools as backend
to create high quality images

-
ChangeLog:


Update information :

* Mon Nov  5 2007 Bruno Postle <bruno postle net> 0.6.1-11
- fix for CVE-2007-5200 hugin unsafe temporary file usage
- bug #332401; bug #362851; bug #362861; bug #362871
- fix Source tag
- update license GPL -> GPLv2+
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5200");
script_summary(english: "Check for the version of the hugin package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"hugin-0.6.1-11.fc7", release:"FC7") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

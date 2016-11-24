
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-9604
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34825);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-9604: grip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-9604 (grip)");
 script_set_attribute(attribute: "description", value: "Grip is a GTK+ based front-end for CD rippers (such as cdparanoia and
cdda2wav) and Ogg Vorbis encoders. Grip allows you to rip entire tracks or
just a section of a track. Grip supports the CDDB protocol for
accessing track information on disc database servers.

-
ChangeLog:


Update information :

* Sun Nov  9 2008 Adrian Reber <adrian lisas de> - 1:3.2.0-24
- fixed 'buffer overflow caused by large amount of CDDB replies' (#470552)
(CVE-2005-0706)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2005-0706");
script_summary(english: "Check for the version of the grip package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"grip-3.2.0-24.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

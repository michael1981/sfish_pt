
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-7491
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40948);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-7491: ocaml-camlimages");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-7491 (ocaml-camlimages)");
 script_set_attribute(attribute: "description", value: "CamlImages is an image processing library for Objective CAML, which provides:
basic functions for image processing and loading/saving, various image file
formats (hence providing a translation facility from format to format),
and an interface with the Caml graphics library allows to display images
in the Graphics module screen and to mix them with Caml drawings

In addition, the library can handle huge images that cannot be (or can hardly
be) stored into the main memory (the library then automatically creates swap
files and escapes them to reduce the memory usage).

-
ChangeLog:


Update information :

* Fri Jul  3 2009 Richard W.M. Jones <rjones redhat com> - 3.0.1-3.fc10.2
- ocaml-camlimages: PNG reader multiple integer overflows
(CVE 2009-2295 / RHBZ#509531).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-2295");
script_summary(english: "Check for the version of the ocaml-camlimages package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ocaml-camlimages-3.0.1-3.fc10.2", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

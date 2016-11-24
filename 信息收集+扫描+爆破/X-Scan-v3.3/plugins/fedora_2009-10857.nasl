
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10857
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42787);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-10857: texlive");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10857 (texlive)");
 script_set_attribute(attribute: "description", value: "TeXLive is an implementation of TeX for Linux or UNIX systems. TeX takes
a text file and a set of formatting commands as input and creates a
printable file as output. Usually, TeX is used in conjunction with
a higher level formatting package like LaTeX or PlainTeX, since TeX by
itself is not very user-friendly.

Install texlive if you want to use the TeX text formatting system. Consider
to install texlive-latex (a higher level formatting package which provides
an easier-to-use interface for TeX).

The TeX documentation is located in the texlive-doc package.

-
ChangeLog:


Update information :

* Fri Oct 23 2009 Jindrich Novy <jnovy redhat com> 2007-46
- add missing dependency on kpathsea
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1284");
script_summary(english: "Check for the version of the texlive package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"texlive-2007-46.fc11", release:"FC11") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-669
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25913);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2007-669: tetex");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-669 (tetex)");
 script_set_attribute(attribute: "description", value: "TeTeX is an implementation of TeX for Linux or UNIX systems. TeX takes
a text file and a set of formatting commands as input and creates a
typesetter-independent .dvi (DeVice Independent) file as output.
Usually, TeX is used in conjunction with a higher level formatting
package like LaTeX or PlainTeX, since TeX by itself is not very
user-friendly. The output format needn't to be DVI, but also PDF,
when using pdflatex or similar tools.

Install tetex if you want to use the TeX text formatting system. Consider
to install tetex-latex (a higher level formatting package which provides
an easier-to-use interface for TeX). Unless you are an expert at using TeX,
you should also install the tetex-doc package, which includes the
documentation for TeX.



Update information :

* Fri Aug 10 2007 Jindrich Novy <jnovy redhat com> 3.0-35
- backport upstream fix for xpdf integer overflow CVE-2007-3387 (#251515)
- don't mess up file contexts while running texhash (#235032)

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3387");
script_summary(english: "Check for the version of the tetex package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"tetex-latex-3.0-35.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-3.0-35.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-3.0-35.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-3.0-35.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-fonts-3.0-35.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-3.0-35.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-3.0-35.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-3308
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(28306);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2007-3308: tetex");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-3308 (tetex)");
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

-
Update Information:

- fix t1lib flaw CVE-2007-4033 (#352271)
- fix CVE-2007-4352 CVE-2007-5392 CVE-2007-5393, various xpdf flaws (#345121)
- fix dvips -z buffer overflow with long href CVE-2007-5935 (#368591)
- fix insecure usage of temporary file in dviljk CVE-2007-5936 CVE-2007-5937 (#
368611, #368641)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3387", "CVE-2007-4033", "CVE-2007-5393", "CVE-2007-5935", "CVE-2007-5936", "CVE-2007-5937");
script_summary(english: "Check for the version of the tetex package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"tetex-3.0-44.3.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

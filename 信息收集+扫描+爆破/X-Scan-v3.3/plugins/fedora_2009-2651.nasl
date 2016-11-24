
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2651
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36287);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-2651: pdfjam");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2651 (pdfjam)");
 script_set_attribute(attribute: "description", value: "PDFjam is a small collection of shell scripts which provide a simple
interface to some of the functionality of the excellent pdfpages
package (by Andreas Matthias) for pdfLaTeX.  At present the utilities
available are:

* pdfnup, which allows PDF files to be 'n-upped' in roughly the way
that psnup does for PostScript files;
* pdfjoin, which concatenates the pages of multiple PDF files
together into a single file;
* pdf90, which rotates the pages of one or more PDF files through 90
degrees (anti-clockwise).

In every case, source files are left unchanged.

A potential drawback of these utilities is that any hyperlinks in the
source PDF are lost. On the positive side, there is no appreciable
degradation of image quality in processing PDF files with these
programs, unlike some other indirect methods such as 'pdf2ps | psnup |
ps2pdf' (in the author's experience).

-
Update Information:

PDFjam scripts previously create temporary files with predictable names, and ar
e
also susceptible to the search path being modified. This update fixes the two
issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5743", "CVE-2008-5843");
script_summary(english: "Check for the version of the pdfjam package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"pdfjam-1.21-1.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

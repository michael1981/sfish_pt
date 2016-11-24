
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41166);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for Cups (11965)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 11965");
 script_set_attribute(attribute: "description", value: 'A number of vulnerabilities have been found in the xpdf code
used by cups which could be exploited, potentially remotely,
by tricking the user to print a specially crafted PDF file.
The vulnerabilities are in the source code file Stream.cc
and may allow execution of arbitrary code with the
privileges of the user viewing the PDF. Specifically, these
are an array indexing error leading to memory corruption
(CVE-2007-4352), a possible integer overflow causing to a
buffer overflow (CVE-2007-5392) and a boundary check error
that can also cause a buffer overflow (CVE-2007-5393).
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch 11965");
script_end_attributes();

script_cve_id("CVE-2007-4352","CVE-2007-5392","CVE-2007-5393");
script_summary(english: "Check for the security advisory #11965");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"cups-1.1.20-108.44", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.20-108.44", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.20-108.44", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.20-108.44", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

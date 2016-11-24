
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27373);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  opera: Security update to version 9.0 (opera-1699)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch opera-1699");
 script_set_attribute(attribute: "description", value: "The webbrowser Opera has been upgraded to version 9.0 to
add lots of new features, and to fix the following security
problem:

CVE-2006-3198: An integer overflow vulnerability exists in
the Opera Web Browser due to the improper handling of JPEG
files.

If excessively large height and width values are specified
in certain fields of a JPEG file, an integer overflow may
cause Opera to allocate insufficient memory for the image.
This will lead to a buffer overflow when the image is
loaded into memory, which can be exploited to execute
arbitrary code.

This updates the previous version, which had a directory
conflict.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch opera-1699");
script_end_attributes();

script_cve_id("CVE-2006-3198");
script_summary(english: "Check for the opera-1699 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"opera-9.0-1.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

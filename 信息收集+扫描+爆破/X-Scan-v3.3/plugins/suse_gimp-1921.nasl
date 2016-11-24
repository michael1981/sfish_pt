
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27234);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  gimp: Securityfix for XCF overflow problem (gimp-1921)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gimp-1921");
 script_set_attribute(attribute: "description", value: "A buffer overflow was fixed in the xcf loader in GIMP that
allows user-complicit attackers to cause a denial of
service (crash) and possibly execute arbitrary code via an
XCF file with a large num_axes value in the VECTORS
property. (CVE-2006-3404)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch gimp-1921");
script_end_attributes();

script_cve_id("CVE-2006-3404");
script_summary(english: "Check for the gimp-1921 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gimp-2.2.10-22.5", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27207);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  ethereal: Fixes several denial of service security problems. (ethereal-2246)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ethereal-2246");
 script_set_attribute(attribute: "description", value: "Various problems have been fixed in the network analyzer
Ethereal, most leading to crashes of the ethereal program.

CVE-2006-5740: A unspecified vulnerability in the LDAP
dissector could be used to crash Ethereal.

CVE-2006-4574: A single \0 byte heap overflow was fixed in
the MIME multipart dissector. Potential of exploitability
is unknown, but considered low.

CVE-2006-4805: A denial of service problem in the XOT
dissector can cause it to take up huge amount of memory and
crash ethereal.

CVE-2006-5469: The WBXML dissector could be used to crash
ethereal.

CVE-2006-5468: A NULL pointer dereference in the HTTP
dissector could crash ethereal.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch ethereal-2246");
script_end_attributes();

script_cve_id("CVE-2006-5740", "CVE-2006-4574", "CVE-2006-4805", "CVE-2006-5469", "CVE-2006-5468");
script_summary(english: "Check for the ethereal-2246 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ethereal-0.10.14-16.11", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ethereal-devel-0.10.14-16.11", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

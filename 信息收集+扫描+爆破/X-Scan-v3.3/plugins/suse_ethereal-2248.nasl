
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29420);
 script_version ("$Revision: 1.7 $");
 script_name(english: "SuSE Security Update:  Security update for ethereal (ethereal-2248)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ethereal-2248");
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
script_set_attribute(attribute: "solution", value: "Install the security patch ethereal-2248");
script_end_attributes();

script_cve_id("CVE-2006-4574", "CVE-2006-4805", "CVE-2006-5468", "CVE-2006-5469", "CVE-2006-5740");
script_summary(english: "Check for the ethereal-2248 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"ethereal-0.10.14-16.11", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.14-16.11", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

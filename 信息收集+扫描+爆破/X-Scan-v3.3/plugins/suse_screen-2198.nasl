
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27433);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  screen: Security problem in UTF-8 combining (screen-2198)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch screen-2198");
 script_set_attribute(attribute: "description", value: "A special formed UTF-8 sequence in text could be used to
crash the terminal multitasker screen by overwriting memory
in the heap. This is potentially exploitable to execute
code. (CVE-2006-4573)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch screen-2198");
script_end_attributes();

script_cve_id("CVE-2006-4573");
script_summary(english: "Check for the screen-2198 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"screen-4.0.2-62.5", release:"SUSE10.1") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

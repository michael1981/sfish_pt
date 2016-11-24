
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29595);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for wv (wv-2280)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch wv-2280");
 script_set_attribute(attribute: "description", value: "Two integer overflows were found in the Microsoft Word
converter library 'wv', which could potentially be used to
crash programs using this library or to even execute code.

- A LVL Count Integer Overflow Vulnerability was fixed.
- A LFO Count Integer Overflow Vulnerability was fixed.

Both problems have been assigned the Mitre CVE ID
CVE-2006-4513.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch wv-2280");
script_end_attributes();

script_cve_id("CVE-2006-4513");
script_summary(english: "Check for the wv-2280 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"wv-1.0.3-20.5", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

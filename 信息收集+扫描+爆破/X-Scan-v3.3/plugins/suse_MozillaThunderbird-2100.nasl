
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27126);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  MozillaThunderbird: Security update to version 1.5.0.7 (MozillaThunderbird-2100)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaThunderbird-2100");
 script_set_attribute(attribute: "description", value: "This security update brings Mozilla Thunderbird to version
1.5.0.7.

More Details can be found on this page:
http://www.mozilla.org/projects/security/known-vulnerabiliti
es.html

It includes fixes to the following security problems: MFSA
2006-64/CVE-2006-4571: Crashes with evidence of memory
corruption MFSA 2006-63/CVE-2006-4570: JavaScript execution
in mail via XBL MFSA 2006-60/CVE-2006-4340/CERT VU#845620:
RSA Signature Forgery MFSA 2006-59/CVE-2006-4253:
Concurrency-related vulnerability MFSA
2006-58/CVE-2006-4567: Auto-Update compromise through DNS
and SSL spoofing MFSA 2006-57/CVE-2006-4565/CVE-2006-4566:
JavaScript Regular Expression Heap Corruption
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaThunderbird-2100");
script_end_attributes();

script_cve_id("CVE-2006-4571", "CVE-2006-4570", "CVE-2006-4340", "CVE-2006-4253", "CVE-2006-4567", "CVE-2006-4565", "CVE-2006-4566");
script_summary(english: "Check for the MozillaThunderbird-2100 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaThunderbird-1.5.0.7-0.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-translations-1.5.0.7-0.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

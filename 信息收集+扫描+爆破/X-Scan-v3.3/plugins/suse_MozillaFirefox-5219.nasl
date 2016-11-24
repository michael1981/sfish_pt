
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32114);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  MozillaFirefox: Security update to version 2.0.0.14 (MozillaFirefox-5219)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaFirefox-5219");
 script_set_attribute(attribute: "description", value: "This update brings Mozilla Firefox to security update
version 2.0.0.14

Following security problems were fixed:
- MFSA 2008-20/CVE-2008-1380: Fixes for security problems
  in the JavaScript engine described in MFSA 2008-15
  (CVE-2008-1237) introduced a stability problem, where
  some users experienced frequent crashes during JavaScript
  garbage collection. These crashes may be exploitable if
  someone finds a reliable way to trigger the crash.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaFirefox-5219");
script_end_attributes();

script_cve_id("CVE-2008-1380", "CVE-2008-1237");
script_summary(english: "Check for the MozillaFirefox-5219 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaFirefox-2.0.0.14-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-2.0.0.14-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

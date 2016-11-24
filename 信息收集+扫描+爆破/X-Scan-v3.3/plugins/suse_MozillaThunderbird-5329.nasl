
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33120);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  MozillaThunderbird: Security fixes (MozillaThunderbird-5329)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaThunderbird-5329");
 script_set_attribute(attribute: "description", value: "Various MozillaThunderbird fixes were backported to the
10.2 version (1.5.0.x).

+ MFSA 2008-15/CVE-2008-1236 and CVE-2008-1237:  Crashes
  with evidence of memory corruption (rv:1.8.1.13)
+ MFSA 2008-14/CVE-2008-1233, CVE-2008-1234, and
  CVE-2008-1235: JavaScript privilege escalation and
  arbitrary code execution.

Javascript is not default enabled in our Thunderbird builds
though.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaThunderbird-5329");
script_end_attributes();

script_cve_id("CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235");
script_summary(english: "Check for the MozillaThunderbird-5329 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaThunderbird-1.5.0.14-0.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-translations-1.5.0.14-0.5", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29694);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  MozillaThunderbird: Security update to version 2.0.0.9 (MozillaThunderbird-4811)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaThunderbird-4811");
 script_set_attribute(attribute: "description", value: "This update brings Mozilla Thunderbird to security update
version 2.0.0.9

Following security problems were fixed:
- MFSA 2007-29: Crashes with evidence of memory corruption
  As part of the Firefox 2.0.0.8 update releases Mozilla
  developers fixed many bugs to improve the stability of
  the product. Some of these crashes showed evidence of
  memory corruption under certain circumstances and we
  presume that with enough effort at least some of these
  could be exploited to run arbitrary code.

  - CVE-2007-5339 Browser crashes
  - CVE-2007-5340 JavaScript engine crashes

Also enigmail was upgraded to 0.95.5.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaThunderbird-4811");
script_end_attributes();

script_cve_id("CVE-2007-5339", "CVE-2007-5340");
script_summary(english: "Check for the MozillaThunderbird-4811 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaThunderbird-2.0.0.9-0.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-translations-2.0.0.9-0.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

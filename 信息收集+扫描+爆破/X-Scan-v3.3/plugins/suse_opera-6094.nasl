
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35957);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  opera security update (opera-6094)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch opera-6094");
 script_set_attribute(attribute: "description", value: "Opera 9.64 is a recommended security and stability upgrade,
incorporating the Opera Presto 2.1.1 user agent engine.
Opera highly recommends all users to upgrade to Opera 9.64
to take advantage of these improvements (CVE-2009-0914,
CVE-2009-0915, CVE-2009-0916).

A detailed changelog can be found at
http://www.opera.com/docs/changelogs/linux/964/
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch opera-6094");
script_end_attributes();

script_cve_id("CVE-2009-0914", "CVE-2009-0915", "CVE-2009-0916");
script_summary(english: "Check for the opera-6094 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"opera-9.64-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

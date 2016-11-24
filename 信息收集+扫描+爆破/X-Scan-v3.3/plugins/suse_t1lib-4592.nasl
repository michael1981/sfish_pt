
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27607);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  t1lib security update (t1lib-4592)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch t1lib-4592");
 script_set_attribute(attribute: "description", value: "A buffer overflow in t1lib could potentially be exploited
to execute arbitrary code via specially crafted files
(CVE-2007-4033).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch t1lib-4592");
script_end_attributes();

script_cve_id("CVE-2007-4033");
script_summary(english: "Check for the t1lib-4592 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"t1lib-5.1.1-15.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"t1lib-devel-5.1.1-15.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

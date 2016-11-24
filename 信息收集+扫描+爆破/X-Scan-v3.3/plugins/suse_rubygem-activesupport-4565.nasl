
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28206);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  rubygem-activesupport security update (rubygem-activesupport-4565)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch rubygem-activesupport-4565");
 script_set_attribute(attribute: "description", value: "A cross site scripting (XSS) bug allowed attackers to
execute Javascript code in the context of other web sites
(CVE-2007-3227).

Specially crafted requests could crash an application when
processing XML data (CVE-2007-5379).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch rubygem-activesupport-4565");
script_end_attributes();

script_cve_id("CVE-2007-3227", "CVE-2007-5379");
script_summary(english: "Check for the rubygem-activesupport-4565 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"rubygem-activesupport-1.4.2-20.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29246);
 script_version ("$Revision: 1.4 $");
 script_name(english: "SuSE Security Update:  htdig security update (htdig-4751)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch htdig-4751");
 script_set_attribute(attribute: "description", value: "A flaw in the htsearch Program could be exploited by
attackers to conduct cross site scripting (XSS) attacks.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch htdig-4751");
script_end_attributes();

script_summary(english: "Check for the htdig-4751 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"htdig-3.2.0b6-110.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"htdig-devel-3.2.0b6-110.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"htdig-doc-3.2.0b6-110.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

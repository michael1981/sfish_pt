
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27346);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  mediawiki: This update fixes a cross-site-scripting bug in mediawiki. (mediawiki-2457)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch mediawiki-2457");
 script_set_attribute(attribute: "description", value: "This update fixes a cross-site-scripting vulnerability when
the AJAX module is enabled (it is switched off by default)
and allows the execution of JavaScript code.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch mediawiki-2457");
script_end_attributes();

script_summary(english: "Check for the mediawiki-2457 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"mediawiki-1.8.2-0.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

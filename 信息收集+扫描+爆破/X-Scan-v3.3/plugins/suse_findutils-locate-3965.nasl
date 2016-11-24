
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27218);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  findutils-locate security update (findutils-locate-3965)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch findutils-locate-3965");
 script_set_attribute(attribute: "description", value: "The cronjob that deletes old core files could be tricked to
delete arbitrary files. Old core files are deleted if
DELETE_OLD_CORE=yes is set. That is not the case by default
though.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch findutils-locate-3965");
script_end_attributes();

script_summary(english: "Check for the findutils-locate-3965 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"findutils-locate-4.2.27-14.15", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

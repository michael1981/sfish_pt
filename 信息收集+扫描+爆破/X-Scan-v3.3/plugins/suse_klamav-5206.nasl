
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32051);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  klamav security update (klamav-5206)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch klamav-5206");
 script_set_attribute(attribute: "description", value: "clamav has been updated due to security problems. The
version number of the clamav library has been changed with
that update. Therefore programs like klamav that are linked
against libclamav need to be updated as well.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch klamav-5206");
script_end_attributes();

script_summary(english: "Check for the klamav-5206 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"klamav-0.41.1-32.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34234);
 script_version ("$Revision: 1.8 $");
 script_name(english: "SuSE Security Update:  Security update for xntp (xntp-5489)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch xntp-5489");
 script_set_attribute(attribute: "description", value: "The ntp daemon did not use supplied keys.

The cause of the problem is that the authentication system
is initialized after the config is parsed and that the
keyfile option is parsed only by storing the keyfile name
for later use when the authentication system is
initialized.  The trustedkey option is handled by
attempting to complete the trusting of the specified keys
(which are not yet loaded). So, all the trusting fails
because it has nothing to act on.

This problem is fixed with this patch.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch xntp-5489");
script_end_attributes();

script_summary(english: "Check for the xntp-5489 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"xntp-4.2.0a-70.22.5", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xntp-doc-4.2.0a-70.22.5", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xntp-4.2.0a-70.22.5", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

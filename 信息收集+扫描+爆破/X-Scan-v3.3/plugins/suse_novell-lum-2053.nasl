
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29530);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for novell-lum (novell-lum-2053)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch novell-lum-2053");
 script_set_attribute(attribute: "description", value: "This patch provides fixes for:
- overwriting user surename with cn
- memory leek
- redundant calls to LDAP
- security vulnerability 
- issue with returning partial list for group members if
  buffer size passed to LUM is too small
- issues related to uninitialized structure/variable when
  LUM runs from the 
- cache and then need to go to LDAP to get data
- potential seg fault under heavy load
- issue with intruder count being incremented 4 times on
  one incorrect login
- users are not case sensitive when not using cache only
  mode
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch novell-lum-2053");
script_end_attributes();

script_summary(english: "Check for the novell-lum-2053 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"novell-lum-2.2.0.6-2.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29372);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for Apache2 (apache2-1906)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch apache2-1906");
 script_set_attribute(attribute: "description", value: "This update fixes security problems in the Apache2
webserver:

mod_rewrite: Fixed an off-by-one security problem in the
ldap scheme handling. For some RewriteRules this could lead
to a pointer being written out of bounds (CVE-2006-3747).

For SUSE Linux Enterprise Server 10 additionaly an old
security problem was fixed: mod_imap: Fixes a
cross-site-scripting bug in the imagemap module
(CVE-2005-3352).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch apache2-1906");
script_end_attributes();

script_cve_id("CVE-2005-3352", "CVE-2006-3747");
script_summary(english: "Check for the apache2-1906 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"apache2-2.2.0-21.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.2.0-21.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.2.0-21.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

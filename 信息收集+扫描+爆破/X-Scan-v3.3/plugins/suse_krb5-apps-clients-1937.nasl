
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27312);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  krb5: Security update to fix missing setuid() return checks (krb5-apps-clients-1937)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch krb5-apps-clients-1937");
 script_set_attribute(attribute: "description", value: "Various return checks of setuid() and seteuid() calls have
been fixed in kerberos client and server applications.

If these applications are setuid, it might have been
possible for local attackers to gain root access
(CVE-2006-3083).

We are not affected by the seteuid() problems, tracked by
CVE-2006-3084.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch krb5-apps-clients-1937");
script_end_attributes();

script_cve_id("CVE-2006-3083", "CVE-2006-3084");
script_summary(english: "Check for the krb5-apps-clients-1937 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"krb5-apps-clients-1.4.3-19.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-apps-servers-1.4.3-19.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

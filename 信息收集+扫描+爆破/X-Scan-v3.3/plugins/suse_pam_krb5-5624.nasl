
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35007);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  pam_krb5 security update (pam_krb5-5624)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch pam_krb5-5624");
 script_set_attribute(attribute: "description", value: "Insufficient file access permissions checks allowed users
to read Kerberos tickes of other users if pam_krb5 was
configured with the option 'existing_ticket'
(CVE-2008-3825).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch pam_krb5-5624");
script_end_attributes();

script_cve_id("CVE-2008-3825");
script_summary(english: "Check for the pam_krb5-5624 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"pam_krb5-2.2.17-14.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"pam_krb5-32bit-2.2.17-14.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"pam_krb5-64bit-2.2.17-14.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40098);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  pam_krb5 (2008-09-19)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for pam_krb5");
 script_set_attribute(attribute: "description", value: "Insufficient file access permissions checks allowed users
to read Kerberos tickes of other users if pam_krb5 was
configured with the option 'existing_ticket'
(CVE-2008-3825).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for pam_krb5");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=425861");
script_end_attributes();

 script_cve_id("CVE-2008-3825");
script_summary(english: "Check for the pam_krb5 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"pam_krb5-2.2.22-35.3", release:"SUSE11.0", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pam_krb5-2.2.22-35.3", release:"SUSE11.0", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pam_krb5-32bit-2.2.22-35.3", release:"SUSE11.0", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

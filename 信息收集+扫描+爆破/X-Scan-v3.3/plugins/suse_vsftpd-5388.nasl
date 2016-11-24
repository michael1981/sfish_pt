
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34079);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for vsftpd (vsftpd-5388)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch vsftpd-5388");
 script_set_attribute(attribute: "description", value: "This update of vsftpd fixes a memory leak that can occur
during authentication. (CVE-2008-2375) Additionally
non-security bugs for SLES10 were fixed. There were some
issues with simultaneous FTP PUT of the same file name that
lead to a corrupted file on the server.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch vsftpd-5388");
script_end_attributes();

script_cve_id("CVE-2008-2375");
script_summary(english: "Check for the vsftpd-5388 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"vsftpd-2.0.4-19.18", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"vsftpd-2.0.4-19.18", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

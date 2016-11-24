
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29538);
 script_version ("$Revision: 1.7 $");
 script_name(english: "SuSE Security Update:  Security update for OpenSSH (openssh-2184)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch openssh-2184");
 script_set_attribute(attribute: "description", value: "Several security problems were fixed in OpenSSH:

- CVE-2006-4924: A denial of service problem has been fixed
  in OpenSSH which could be used to cause lots of CPU
  consumption on a remote openssh server.
- CVE-2006-4925: If a remote attacker is able to inject
  network traffic this could be used to cause a client
  connection to close.
- CVE-2006-5051: Fixed an unsafe signal hander reported by
  Mark Dowd. The signal handler was vulnerable to a race
  condition that could be exploited to perform a
  pre-authentication denial of service. This vulnerability
  could theoretically lead to pre-authentication remote
  code execution if GSSAPI authentication is enabled, but
  the likelihood of successful exploitation appears remote.
- CVE-2006-5052: Fixed a GSSAPI authentication abort that
  could be used to determine the validity of usernames on
  some platforms.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch openssh-2184");
script_end_attributes();

script_cve_id("CVE-2006-4924", "CVE-2006-4925", "CVE-2006-5051", "CVE-2006-5052");
script_summary(english: "Check for the openssh-2184 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"openssh-4.2p1-18.9", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.2p1-18.9", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openssh-4.2p1-18.9", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.2p1-18.9", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

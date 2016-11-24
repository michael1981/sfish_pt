
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27589);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  openssh: This update fixes a bug in ssh's cookie and signal handling code. (openssh-4579)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch openssh-4579");
 script_set_attribute(attribute: "description", value: "This update fixes a bug in ssh's cookie handling code. It
does not properly handle the situation when an untrusted
cookie cannot be created and uses a trusted X11 cookie
instead. This allows attackers to violate the intended
policy and gain privileges by causing an X client to be
treated as trusted. (CVE-2007-4752) Additionally this
update fixes a bug introduced with the last security update
for openssh. When the SSH daemon wrote to stderr (for
instance, to warn about the presence of a deprecated option
like PAMAuthenticationViaKbdInt in its configuration file),
SIGALRM was blocked for SSH sessions. This resulted in
problems with processes which rely on SIGALRM, such as
ntpdate.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch openssh-4579");
script_end_attributes();

script_cve_id("CVE-2007-4752");
script_summary(english: "Check for the openssh-4579 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"openssh-4.6p1-58.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.6p1-58.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

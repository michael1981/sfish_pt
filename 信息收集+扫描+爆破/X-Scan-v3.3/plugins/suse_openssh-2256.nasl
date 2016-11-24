
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27366);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  openssh: Security fix for CVE-2006-5794 (openssh-2256)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch openssh-2256");
 script_set_attribute(attribute: "description", value: "The OpenSSH release 4.5 contains a security fix which has
been backported to the openssh versions in our old products.

CVE-2006-5794: Incorrect return argument checking in the
privilege separation monitor was fixed. In case of an
exploitable unprivileged helper this could have been used
to elevate privileges.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch openssh-2256");
script_end_attributes();

script_cve_id("CVE-2006-5794");
script_summary(english: "Check for the openssh-2256 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"openssh-4.2p1-18.12", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.2p1-18.12", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

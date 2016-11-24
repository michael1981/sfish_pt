
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41258);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for IBM Java2 JRE and SDK (12313)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 12313");
 script_set_attribute(attribute: "description", value: 'IBM Java 1.4.2 SR12 fixes the following security problems:
CVE-2008-3104: Security vulnerabilities in the Java Runtime
Environment may allow an untrusted applet that is loaded from a
remote system to circumvent network access restrictions and
establish socket connections to certain services running on the
local host, as if it were loaded from the system that the applet
is running on. This may allow the untrusted remote applet the
ability to exploit any security vulnerabilities existing in the
services it has connected to.
CVE-2008-3112: A vulnerability in Java Web Start may allow an
untrusted Java Web Start application downloaded from a website to
create arbitrary files with the permissions of the user running
the untrusted Java Web Start application.
CVE-2008-3113: A vulnerability in Java Web Start may allow an
untrusted Java Web Start application downloaded from a website to
create or delete arbitrary files with the permissions of the user
running the untrusted Java Web Start application.
CVE-2008-3114: A vulnerability in Java Web Start may allow an
untrusted Java Web Start application to determine the location of
the Java Web Start cache.
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch 12313");
script_end_attributes();

script_cve_id("CVE-2008-3104","CVE-2008-3112","CVE-2008-3113","CVE-2008-3114");
script_summary(english: "Check for the security advisory #12313");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"IBMJava2-JRE-1.4.2-0.131", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"IBMJava2-SDK-1.4.2-0.131", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

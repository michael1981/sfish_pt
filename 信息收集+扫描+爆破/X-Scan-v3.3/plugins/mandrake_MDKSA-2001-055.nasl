
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13872);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2001:055-1: xinetd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2001:055-1 (xinetd).");
 script_set_attribute(attribute: "description", value: "A bug exists in xinetd as shipped with Mandrake Linux 8.0 dealing with
TCP connections with the WAIT state that prevents linuxconf-web from
working properly. As well, xinetd contains a security flaw in which
it defaults to a umask of 0. This means that applications using the
xinetd umask that do not set permissions themselves (like SWAT, a web
configuration tool for Samba), will create world writable files. This
update sets the default umask to 022.
Update:
This update forces the TMPDIR to /tmp instead of obtaining it from the
root user by default, which uses /root/tmp. As well, this version of
xinetd also fixed a possible buffer overflow in the logging code that
was reported by zen-parse on bugtraq, but was not mentioned in the
previous advisory.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:055-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the xinetd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xinetd-2.3.0-1.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xinetd-2.3.0-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xinetd-ipv6-2.3.0-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13913);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2002:005: proftpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:005 (proftpd).");
 script_set_attribute(attribute: "description", value: "Matthew S. Hallacy discovered that ProFTPD was not forward resolving
reverse-resolved hostnames. A remote attacker could exploit this to
bypass ProFTPD access controls or have false information logged. Frank
Denis discovered that a remote attacker could send malicious commands
to the ProFTPD server and it would force the process to consume all CPU
and memory resources available to it. This DoS vulnerability could
bring the server down with repeated attacks. Finally, Mattias found a
segmentation fault problem that is considered by the developers to be
unexploitable.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:005");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the proftpd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"proftpd-1.2.5-0.rc1.1.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-1.2.5-0.rc1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"proftpd-1.2.5-0.rc1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38066);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:232: dovecot");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:232 (dovecot).");
 script_set_attribute(attribute: "description", value: "The ACL plugin in dovecot prior to version 1.1.4 treated negative
access rights as though they were positive access rights, which allowed
attackers to bypass intended access restrictions (CVE-2008-4577).
The ACL plugin in dovecot prior to version 1.1.4 allowed attackers to
bypass intended access restrictions by using the 'k' right to create
unauthorized 'parent/child/child' mailboxes (CVE-2008-4578).
In addition, two bugs were discovered in the dovecot package shipped
with Mandriva Linux 2009.0. The default permissions on the dovecot.conf
configuration file were too restrictive, which prevents the use of
dovecot's 'deliver' command as a non-root user. Secondly, dovecot
should not start until after ntpd, if ntpd is active, because if ntpd
corrects the time backwards while dovecot is running, dovecot will
quit automatically, with the log message 'Time just moved backwards
by X seconds. This might cause a lot of problems, so I'll just kill
myself now.' The update resolves both these problems. The default
permissions on dovecot.conf now allow the 'deliver' command to read the
file. Note that if you edited dovecot.conf at all prior to installing
the update, the new permissions may not be applied. If you find the
'deliver' command still does not work following the update, please
run these commands as root:
# chmod 0640 /etc/dovecot.conf
# chown root:mail /etc/dovecot.conf
Dovecot's initialization script now configures it to start after the
ntpd service, to ensure ntpd resetting the clock does not interfere
with Dovecot operation.
This package corrects the above-noted bugs and security issues by
upgrading to the latest dovecot 1.1.6, which also provides additional
bug fixes.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:232");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-4577", "CVE-2008-4578");
script_summary(english: "Check for the version of the dovecot package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dovecot-1.1.6-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dovecot-devel-1.1.6-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dovecot-plugins-gssapi-1.1.6-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dovecot-plugins-ldap-1.1.6-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"dovecot-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-4577", value:TRUE);
 set_kb_item(name:"CVE-2008-4578", value:TRUE);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37526);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:009-1: autofs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:009-1 (autofs).");
 script_set_attribute(attribute: "description", value: "The default behaviour of autofs 5 for the hosts map did not specify the
nosuid and nodev mount options. This could allow a local user with
control of a remote NFS server to create a setuid root executable on
the exported filesystem of the remote NFS server. If this filesystem
was mounted with the default hosts map, it would allow the user to
obtain root privileges (CVE-2007-5964). Likewise, the same scenario
would be available for local users able to create device files on
the exported filesystem which could allow the user to gain access to
important system devices (CVE-2007-6285).
Because the default behaviour of autofs was to mount -hosts map
entries with the dev and suid options enabled by default, autofs has
been altered to always use nodev and nosuid by default. In order
to have the old behaviour, the configuration must now explicitly set
the dev and/or suid options.
This change only affects the -hosts map which corresponds to the /net
entry in the default configuration.
Update:
The previous update shipped with an incorrect LDAP lookup module
that would prevent the automount daemon from starting. This update
corrects that problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:009-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-5964", "CVE-2007-6285");
script_summary(english: "Check for the version of the autofs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"autofs-5.0.2-8.4mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"autofs-5.0.2-8.4mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"autofs-", release:"MDK2007.1")
 || rpm_exists(rpm:"autofs-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2007-5964", value:TRUE);
 set_kb_item(name:"CVE-2007-6285", value:TRUE);
}
exit(0, "Host is not affected");

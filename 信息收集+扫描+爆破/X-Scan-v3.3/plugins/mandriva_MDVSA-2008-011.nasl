
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36432);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:011: rsync");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:011 (rsync).");
 script_set_attribute(attribute: "description", value: "rsync before 3.0.0pre6, when running a writable rsync daemon that is
not using chroot, allows remote attackers to access restricted files
via unknown vectors that cause rsync to create a symlink that points
outside of the module's hierarchy. (CVE-2007-6199)
Unspecified vulnerability in rsync before 3.0.0pre6, when running a
writable rsync daemon, allows remote attackers to bypass exclude,
exclude_from, and filter and read or write hidden files via (1)
symlink, (2) partial-dir, (3) backup-dir, and unspecified (4) dest
options. (CVE-2007-6200)
This update fixes these issues. It is recommended users (specially
system and network administrators) read the manpage about the
introduced munge symlinks feature.
This update also upgrades rsync to version 2.6.9 for all Mandriva
Linux versions earlier than 2008.0.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:011");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-6199", "CVE-2007-6200");
script_summary(english: "Check for the version of the rsync package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"rsync-2.6.9-0.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rsync-2.6.9-1.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rsync-2.6.9-5.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"rsync-", release:"MDK2007.0")
 || rpm_exists(rpm:"rsync-", release:"MDK2007.1")
 || rpm_exists(rpm:"rsync-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2007-6199", value:TRUE);
 set_kb_item(name:"CVE-2007-6200", value:TRUE);
}
exit(0, "Host is not affected");

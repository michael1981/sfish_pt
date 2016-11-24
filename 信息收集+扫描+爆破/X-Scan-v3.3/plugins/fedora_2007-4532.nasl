
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-4532
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(29715);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2007-4532: autofs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-4532 (autofs)");
 script_set_attribute(attribute: "description", value: "autofs is a daemon which automatically mounts filesystems when you use
them, and unmounts them later when you are not using them.  This can
include network filesystems, CD-ROMs, floppies, and so forth.

-
ChangeLog:


Update information :

* Thu Dec 13 2007 Ian Kent <ikent redhat com> - 5.0.2-20
- Bug 409701: CVE-2007-5964 Privilege Escalation (from local system) through /n
et autofs mount configuration bug
- use mount option 'nosuid' for '-hosts' map unless 'suid' is explicily speci
fied.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5964");
script_summary(english: "Check for the version of the autofs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"autofs-5.0.2-20", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

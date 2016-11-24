
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-10755
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35385);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-10755: am-utils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-10755 (am-utils)");
 script_set_attribute(attribute: "description", value: "Am-utils includes an updated version of Amd, the popular BSD
automounter.  An automounter is a program which maintains a cache
of mounted filesystems.  Filesystems are mounted when they are
first referenced by the user and unmounted after a certain period of
inactivity. Amd supports a variety of filesystems, including NFS, UFS,
CD-ROMS and local drives.

You should install am-utils if you need a program for automatically
mounting and unmounting filesystems.

-
ChangeLog:


Update information :

* Tue Dec  2 2008 Karel Zak <kzak redhat com> 5:6.1.5-8.1
- fix #450754 - Amd does not work with 2.6.25 (thanks to Philippe Troin)
- fix #435420 - CVE-2008-1078 am-utils: insecure usage of temporary files
- fix autotools stuff
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1078");
script_summary(english: "Check for the version of the am-utils package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"am-utils-6.1.5-8.1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

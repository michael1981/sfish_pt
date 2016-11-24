
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2295
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27764);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2007-2295: fuse");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2295 (fuse)");
 script_set_attribute(attribute: "description", value: "With FUSE it is possible to implement a fully functional filesystem in a
userspace program. This package contains the FUSE userspace tools to
mount a FUSE filesystem.

Note: For security reasons only members of the group 'fuse' are allowed to
(u)mount fuse filesystems. You can find more details on this issue in
/usr/share/doc/fuse-2.7.0/README.fedora

-
Update Information:

It was discovered that members of the group fuse can get access to devices whic
h they normally should not have access to. For ntfs-3g mounts, this was because
/sbin/mount.ntfs-3g was setuid root.    This update fixes /sbin/mount.ntfs-3g
so that it is no longer has the setuid bit enabled. The fuse package is also be
ing updated to correct an error in the previous testing package which incorrect
ly changed the permissions on /dev/fuse.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the fuse package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"fuse-2.7.0-5.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7973
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34183);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-7973: pam_mount");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7973 (pam_mount)");
 script_set_attribute(attribute: "description", value: "This module is aimed at environments with central file servers that a
user wishes to mount on login and unmount on logout, such as
(semi-)diskless stations where many users can logon.

The module also supports mounting local filesystems of any kind the
normal mount utility supports, with extra code to make sure certain
volumes are set up properly because often they need more than just a
mount call, such as encrypted volumes. This includes SMB/CIFS, NCP,
davfs2, FUSE, losetup crypto, dm-crypt/cryptsetup and truecrypt.

If you intend to use pam_mount to protect volumes on your computer
using an encrypted filesystem system, please know that there are many
other issues you need to consider in order to protect your data.  For
example, you probably want to disable or encrypt your swap partition.
Don't assume a system is secure without carefully considering
potential threats.

-
Update Information:

A security flaw in the pam_mount's handling of user defined volumes using the
'luserconf' option has been fixed in this update. The vulnerability allowed
users to arbitrarily mount filesystems at arbitrary locations.    More details
about this vulnerability can be found in the announcement message sent to the
pam-mount-user mailinglist at SourceForge: [9]http://sourceforge.net/mailarchiv
e/me
ssage.php?msg_name=alpine.LNX.1.10.0809042353120.17569%40fbirervta.pbzchgretzou
.
qr    The pam_mount facility now uses a configuration file written in XML. The
/etc/security/pam_mount.conf file will be converted to
/etc/security/pam_mount.conf.xml  during update with
/usr/bin/convert_pam_mount_conf.pl, which removes all comments. Any per-user
configuration files must be converted manually, with the conversion script if
desired. A sample pam_mount.conf.xml file with detailed comments about the
available options appears at /usr/share/doc/pam_mount-*/pam_mount.conf.xml.
Note: This update also introduces a new version of libHX, which is required by
updated pam_mount.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the pam_mount package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"pam_mount-0.47-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

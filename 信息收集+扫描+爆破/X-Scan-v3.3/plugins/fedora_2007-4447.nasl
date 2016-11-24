
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-4447
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(30025);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2007-4447: e2fsprogs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-4447 (e2fsprogs)");
 script_set_attribute(attribute: "description", value: "The e2fsprogs package contains a number of utilities for creating,
checking, modifying, and correcting any inconsistencies in second
and third extended (ext2/ext3) filesystems. E2fsprogs contains
e2fsck (used to repair filesystem inconsistencies after an unclean
shutdown), mke2fs (used to initialize a partition to contain an
empty ext2 filesystem), debugfs (used to examine the internal
structure of a filesystem, to manually repair a corrupted
filesystem, or to create test cases for e2fsck), tune2fs (used to
modify filesystem parameters), and most of the other core ext2fs
filesystem utilities.

You should install the e2fsprogs package if you need to manage the
performance of an ext2 and/or ext3 filesystem.

-
Update Information:

CVE-2007-5497
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5497");
script_summary(english: "Check for the version of the e2fsprogs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"e2fsprogs-1.40.2-12.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

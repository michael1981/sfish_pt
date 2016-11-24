
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-1584
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31073);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-1584: duplicity");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-1584 (duplicity)");
 script_set_attribute(attribute: "description", value: "Duplicity incrementally backs up files and directory by encrypting
tar-format volumes with GnuPG and uploading them to a remote (or
local) file server. In theory many protocols for connecting to a
file server could be supported; so far ssh/scp, local file access,
rsync, ftp, HSI, WebDAV and Amazon S3 have been written.

Because duplicity uses librsync, the incremental archives are space
efficient and only record the parts of files that have changed since
the last backup. Currently duplicity supports deleted files, full
unix permissions, directories, symbolic links, fifos, device files,
but not hard links.

-
Update Information:

WARNING: Command line syntax incompatibility!    See e.g.
[9]https://www.redhat.com/archives/epel-devel-list/2008-February/msg00056.html
for
furhter information.     - Upgrade to 0.4.9  - Duplicity discloses password in
FTP backend (CVE-2007-5201)  - Several bug and problem fixes
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5201");
script_summary(english: "Check for the version of the duplicity package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"duplicity-0.4.9-1.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

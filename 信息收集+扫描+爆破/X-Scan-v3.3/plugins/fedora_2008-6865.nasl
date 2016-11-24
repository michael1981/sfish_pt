
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6865
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33777);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2008-6865: filezilla");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6865 (filezilla)");
 script_set_attribute(attribute: "description", value: "FileZilla is a FTP, FTPS and SFTP client for Linux with a lot of features.
- Supports FTP, FTP over SSL/TLS (FTPS) and SSH File Transfer Protocol (SFTP)
- Cross-platform
- Available in many languages
- Supports resume and transfer of large files >4GB
- Easy to use Site Manager and transfer queue
- Drag & drop support
- Speed limits
- Filename filters
- Network configuration wizard

-
Update Information:

According to the NEWS in this release:  ----------------  ! Do not report
success on SSL/TLS transfers if server did not perform orderly SSL/TLS shutdown
.
Previously, an attacker could cause truncated files with FileZilla thinking the
transfer was successful. All versions prior to this were affected
----------------  None SA number has been mentioned yet.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the filezilla package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"filezilla-3.1.0.1-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

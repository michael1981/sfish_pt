
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-807
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24148);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2006-807: samba");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-807 (samba)");
 script_set_attribute(attribute: "description", value: "
Samba is the suite of programs by which a lot of PC-related machines
share files, printers, and other information (such as lists of
available files and printers). The Windows NT, OS/2, and Linux
operating systems support this natively, and add-on packages can
enable the same thing for DOS, Windows, VMS, UNIX of all kinds, MVS,
and more. This package provides an SMB server that can be used to
provide network services to SMB (sometimes called 'Lan Manager')
clients. Samba uses NetBIOS over TCP/IP (NetBT) protocols and does NOT
need the NetBEUI (Microsoft Raw NetBIOS frame) protocol.



Update information :

* Wed Jul 12 2006 Jay Fenlason <fenlason redhat com> 3.0.23-1.fc5
- Upgrade to 3.0.23 to close
bz#197836 CVE-2006-3403 Samba denial of service
- include related spec file, filter-requires-samba.sh and patch changes
from rawhide.
- include the fixed smb.init file from rawhide, closing
bz#182560 Wrong retval for initscript when smbd is dead

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-3403");
script_summary(english: "Check for the version of the samba package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"samba-swat-3.0.23-1.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.23-1.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

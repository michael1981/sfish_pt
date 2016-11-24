
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-10638
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35015);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-10638: samba");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-10638 (samba)");
 script_set_attribute(attribute: "description", value: "
Samba is the suite of programs by which a lot of PC-related machines
share files, printers, and other information (such as lists of
available files and printers). The Windows NT, OS/2, and Linux
operating systems support this natively, and add-on packages can
enable the same thing for DOS, Windows, VMS, UNIX of all kinds, MVS,
and more. This package provides an SMB/CIFS server that can be used to
provide network services to SMB/CIFS clients.
Samba uses NetBIOS over TCP/IP (NetBT) protocols and does NOT
need the NetBEUI (Microsoft Raw NetBIOS frame) protocol.

-
Update Information:

[9]http://www.samba.org/samba/security/CVE-2008-4314.html
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-4572", "CVE-2007-5398", "CVE-2007-6015", "CVE-2008-1105", "CVE-2008-4314");
script_summary(english: "Check for the version of the samba package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"samba-3.0.33-0.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

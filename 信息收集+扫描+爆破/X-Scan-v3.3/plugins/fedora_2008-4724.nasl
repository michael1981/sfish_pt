
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-4724
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32485);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-4724: samba");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-4724 (samba)");
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

Fix CVE-2008-1105    A heap-based buffer overflow flaw has been found in the wa
y
Samba clients handle over-sized packets. If a client connected to a malicious
Samba server, it was possible to execute arbitrary code as the Samba client
user.    The Samba server can also act as a client to perform some operations
(print notify, domain member vs domain controler ...). This could result in the
server executing the vulnerable client code, resulting in arbitrary code
execution with the permissions of the Samba server.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1105");
script_summary(english: "Check for the version of the samba package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"samba-3.2.0-1.rc1.14.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

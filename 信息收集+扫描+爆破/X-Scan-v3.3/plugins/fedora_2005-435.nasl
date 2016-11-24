#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19464);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-1079", "CVE-2005-0013", "CVE-2005-0014");
 
 name["english"] = "Fedora Core 3 2005-435: ncpfs";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-435 (ncpfs).

Ncpfs is a filesystem which understands the Novell NetWare(TM) NCP
protocol. Functionally, NCP is used for NetWare the way NFS is used
in the TCP/IP world. For a Linux system to mount a NetWare
filesystem, it needs a special mount program. The ncpfs package
contains such a mount program plus other tools for configuring and
using the ncpfs filesystem.

Install the ncpfs package if you need to use the ncpfs filesystem
to use Novell NetWare files or services.


* Fri Jun 17 2005 Jiri Ryska 2.2.4-4.FC3.1

- fixed getuid security bug CVE-2005-0014
- fixed security bug CVE-2004-1079

* Mon Apr 11 2005 Jiri Ryska 2.2.4-4.FC3

- fixed getuid security bug CVE-2005-0013" );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/blog/index.php?p=843" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the ncpfs package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ncpfs-2.2.4-4.FC3.1", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ipxutils-2.2.4-4.FC3.1", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ncpfs-debuginfo-2.2.4-4.FC3.1", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"ncpfs-", release:"FC3") )
{
 set_kb_item(name:"CVE-2004-1079", value:TRUE);
 set_kb_item(name:"CVE-2005-0013", value:TRUE);
 set_kb_item(name:"CVE-2005-0014", value:TRUE);
}

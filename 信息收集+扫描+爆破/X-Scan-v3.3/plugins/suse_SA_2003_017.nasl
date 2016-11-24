#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:017
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13787);
 script_bugtraq_id(7008);
 script_bugtraq_id(7009);
 script_version ("$Revision: 1.16 $");
 
 name["english"] = "SUSE-SA:2003:017: file";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:017 (file).


The file command can be used to determine the type of files.
iDEFENSE published a security report about a buffer overflow in the
handling-routines for the ELF file-format.
In conjunction with other mechanisms like print-filters, cron-jobs,
eMail-scanners (like AMaViS) and alike this vulnerability can be used
to gain higher privileges or to compromise the system remotely.

There is no temporary fix known other then updating the system.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_017_file.html" );
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");



 script_end_attributes();

 
 summary["english"] = "Check for the version of the file package";
 script_cve_id("CVE-2003-0102", "CVE-2003-1092");
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"file-3.32-118", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"file-3.33-85", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"file-3.37-206", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"file-3.37-206", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"file-", release:"SUSE7.1")
 || rpm_exists(rpm:"file-", release:"SUSE7.3")
 || rpm_exists(rpm:"file-", release:"SUSE8.0")
 || rpm_exists(rpm:"file-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0102", value:TRUE);
}

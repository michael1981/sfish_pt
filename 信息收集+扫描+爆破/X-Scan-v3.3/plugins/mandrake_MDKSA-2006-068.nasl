
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21203);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:068: mplayer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:068 (mplayer).");
 script_set_attribute(attribute: "description", value: "Multiple integer overflows in MPlayer 1.0pre7try2 allow remote
attackers to cause a denial of service and trigger heap-based buffer
overflows via (1) a certain ASF file handled by asfheader.c that causes
the asf_descrambling function to be passed a negative integer after the
conversion from a char to an int or (2) an AVI file with a crafted
wLongsPerEntry or nEntriesInUse value in the indx chunk, which is
handled in aviheader.c.
The updated packages have been patched to prevent this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:068");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-1502");
script_summary(english: "Check for the version of the mplayer package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libdha1.0-1.0-1.pre7.12.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-1.0-1.pre7.12.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-devel-1.0-1.pre7.12.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mencoder-1.0-1.pre7.12.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-1.0-1.pre7.12.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-1.0-1.pre7.12.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mplayer-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1502", value:TRUE);
}
exit(0, "Host is not affected");

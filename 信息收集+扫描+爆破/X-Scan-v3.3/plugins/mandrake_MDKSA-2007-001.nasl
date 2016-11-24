
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24618);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:001: libmodplug");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:001 (libmodplug).");
 script_set_attribute(attribute: "description", value: "Multiple buffer overflows in MODPlug Tracker (OpenMPT) 1.17.02.43 and
earlier and libmodplug 0.8 and earlier allow user-assisted remote
attackers to execute arbitrary code via (1) long strings in ITP files
used by the CSoundFile::ReadITProject function in soundlib/Load_it.cpp
and (2) crafted modules used by the CSoundFile::ReadSample function in
soundlib/Sndfile.cpp, as demonstrated by crafted AMF files.
Updated packages are patched to address this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:001");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-4192");
script_summary(english: "Check for the version of the libmodplug package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libmodplug0-0.7-7.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmodplug0-devel-0.7-7.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libmodplug-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-4192", value:TRUE);
}
exit(0, "Host is not affected");

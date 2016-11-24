
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40126);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  samba (2008-08-28)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for samba");
 script_set_attribute(attribute: "description", value: "This is an update to version 3.2.3 of Samba.

This release includes several bugfixes and performance
enhancements for Samba and its components. It is
recommended for every user to update to this version.

Among several other bugs the following list shows some
detail:
- Fix a race condition in winbind leading to a crash
  (bnc#406623).
- Fix emptying the printing queue; (bnc#411493).
- Fix the webinface SWAT; (bnc#391969).
- Fixed a file permission problem. (CVE-2008-3789)
  bnc#420634
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for samba");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=412589");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=411493");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=406623");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=391969");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=420634");
script_end_attributes();

 script_cve_id("CVE-2008-3789");
script_summary(english: "Check for the samba package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"cifs-mount-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cifs-mount-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ldapsmb-1.34b-195.4", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ldapsmb-1.34b-195.4", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libnetapi-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libnetapi-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libnetapi0-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libnetapi0-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libsmbclient-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libsmbclient-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libsmbclient0-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libsmbclient0-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libsmbclient0-32bit-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libsmbsharemodes-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libsmbsharemodes-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libsmbsharemodes0-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libsmbsharemodes0-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libtalloc-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libtalloc-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libtalloc1-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libtalloc1-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libtalloc1-32bit-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libtdb-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libtdb-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libtdb1-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libtdb1-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libtdb1-32bit-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libwbclient-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libwbclient-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libwbclient0-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libwbclient0-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libwbclient0-32bit-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-32bit-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-client-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-client-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-client-32bit-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-devel-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-doc-3.2.3-0.1", release:"SUSE11.0", cpu:"noarch") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-krb-printing-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-krb-printing-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-3.2.3-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-32bit-3.2.3-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");

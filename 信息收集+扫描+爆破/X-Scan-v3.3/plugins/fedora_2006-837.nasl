
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-837
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24154);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2006-837: sendmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-837 (sendmail)");
 script_set_attribute(attribute: "description", value: "The Sendmail program is a very widely used Mail Transport Agent (MTA).
MTAs send mail from one machine to another. Sendmail is not a client
program, which you use to read your email. Sendmail is a
behind-the-scenes program which actually moves your email over
networks or the Internet to where you want it to go.

If you ever need to reconfigure Sendmail, you will also need to have
the sendmail.cf package installed. If you need documentation on
Sendmail, you can install the sendmail-doc package.



Update information :

* Tue Jul 18 2006 Thomas Woerner <twoerner redhat com> 8.13.7-2.fc5.1
- using new syntax for access database (#177566)
- fixed failure message while shutting down sm-client (#119429)
resolution: stop sm-client before sendmail
- fixed method to specify persistent queue runners (#126760)
- removed patch backup files from sendmail-cf tree (#152955)
- fixed missing dnl on SMART_HOST define (#166680)
- fixed wrong location of aliases and aliases.db file in aliases man page
(#166744)
- enabled CipherList config option for sendmail (#172352)
- added user chowns for /etc/mail/authinfo.db and move check for cf files
(#184341)
- fixed Makefile of vacation (#191396)
vacation is not included in this sendmail package
- /var/log/mail now belongs to sendmail (#192850)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-1173");
script_summary(english: "Check for the version of the sendmail package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"sendmail-8.13.7-2.fc5.1", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

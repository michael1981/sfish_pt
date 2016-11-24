# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(14459);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200403-08");
 script_cve_id("CVE-2004-0376");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200403-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200403-08
(oftpd DoS vulnerability)


    Issuing a port command with a number higher than 255 causes the server
    to crash. The port command may be issued before any authentication
    takes place, meaning the attacker does not need to know a valid
    username and password in order to exploit this vulnerability.
  
Impact

    This exploit causes a denial of service.
  
Workaround

    While a workaround is not currently known for this issue, all users are
    advised to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the current version of the affected
    package:
    # emerge sync
    # emerge -pv ">=net-ftp/oftpd-0.3.7"
    # emerge ">=net-ftp/oftpd-0.3.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.time-travellers.org/oftpd/');
script_set_attribute(attribute: 'see_also', value: 'http://www.time-travellers.org/oftpd/oftpd-dos.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0376');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200403-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200403-08] oftpd DoS vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'oftpd DoS vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-ftp/oftpd", unaffected: make_list("ge 0.3.7"), vulnerable: make_list("le 0.3.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

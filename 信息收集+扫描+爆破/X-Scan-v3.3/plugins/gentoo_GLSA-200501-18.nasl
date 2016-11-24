# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-18.xml
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
 script_id(16409);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200501-18");
 script_cve_id("CVE-2004-1165");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-18
(KDE FTP KIOslave: Command injection)


    The FTP KIOslave fails to properly parse URL-encoded newline
    characters.
  
Impact

    An attacker could exploit this to execute arbitrary FTP commands on the
    server and due to similiarities between the FTP and the SMTP protocol,
    this vulnerability also allows an attacker to connect to a SMTP server
    and issue arbitrary commands, for example sending an email.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All kdelibs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdelibs
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.kde.org/info/security/advisory-20050101-1.txt');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1165');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-18] KDE FTP KIOslave: Command injection');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KDE FTP KIOslave: Command injection');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/kdelibs", unaffected: make_list("ge 3.3.2-r2", "rge 3.2.3-r5"), vulnerable: make_list("lt 3.3.2-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

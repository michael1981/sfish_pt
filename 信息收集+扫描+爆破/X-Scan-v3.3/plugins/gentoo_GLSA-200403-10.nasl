# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-10.xml
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
 script_id(14461);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200403-10");
 script_cve_id("CVE-2003-0792");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200403-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200403-10
(Fetchmail 6.2.5 fixes a remote DoS)


    Fetchmail versions 6.2.4 and earlier can be crashed by sending a
    specially-crafted email to a fetchmail user. This problem occurs because
    Fetchmail does not properly allocate memory for long lines in an incoming
    email.
  
Impact

    Fetchmail users who receive a malicious email may have their fetchmail
    program crash.
  
Workaround

    While a workaround is not currently known for this issue, all users are advised to upgrade to the latest version of fetchmail.
  
');
script_set_attribute(attribute:'solution', value: '
    Fetchmail users should upgrade to version 6.2.5 or later:
    # emerge sync
    # emerge -pv ">=net-mail/fetchmail-6.2.5"
    # emerge ">=net-mail/fetchmail-6.2.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://xforce.iss.net/xforce/xfdb/13450');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2003-0792');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200403-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200403-10] Fetchmail 6.2.5 fixes a remote DoS');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Fetchmail 6.2.5 fixes a remote DoS');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/fetchmail", unaffected: make_list("ge 6.2.5"), vulnerable: make_list("le 6.2.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-01.xml
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
 script_id(22939);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200611-01");
 script_cve_id("CVE-2006-4573");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-01
(Screen: UTF-8 character handling vulnerability)


    cstone and Richard Felker discovered a flaw in Screen\'s UTF-8 combining
    character handling.
  
Impact

    The vulnerability can be exploited by writing a special string of
    characters to a Screen window. A remote attacker could cause a Denial
    of Service or possibly execute arbitrary code with the privileges of
    the user running Screen through a program being run inside a Screen
    session, such as an IRC client or a mail client.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Screen users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-misc/screen-4.0.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4573');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-01] Screen: UTF-8 character handling vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Screen: UTF-8 character handling vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-misc/screen", unaffected: make_list("ge 4.0.3"), vulnerable: make_list("lt 4.0.3")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200907-16.xml
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
 script_id(39870);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200907-16");
 script_cve_id("CVE-2008-5031");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200907-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200907-16
(Python: Integer overflows)


    Chris Evans reported multiple integer overflows in the expandtabs
    method, as implemented by (1) the string_expandtabs function in
    Objects/stringobject.c and (2) the unicode_expandtabs function in
    Objects/unicodeobject.c.
  
Impact

    A remote attacker could exploit these vulnerabilities in Python
    applications or daemons that pass user-controlled input to vulnerable
    functions. The security impact is currently unknown but may include the
    execution of arbitrary code or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Python 2.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/python-2.5.4-r2"
    All Python 2.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/python-2.4.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5031');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200907-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200907-16] Python: Integer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Python: Integer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/python", unaffected: make_list("ge 2.5.4-r2", "rge 2.4.6"), vulnerable: make_list("lt 2.5.4-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

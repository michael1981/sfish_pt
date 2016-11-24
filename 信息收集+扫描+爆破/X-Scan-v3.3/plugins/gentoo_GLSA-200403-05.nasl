# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-05.xml
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
 script_id(14456);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200403-05");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200403-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200403-05
(UUDeview MIME Buffer Overflow)


    By decoding a MIME archive with excessively long strings for various
    parameters, it is possible to crash UUDeview, or cause it to execute
    arbitrary code.
    This vulnerability was originally reported by iDEFENSE as part of a WinZip
    advisory [ Reference: 1 ].
  
Impact

    An attacker could create a specially-crafted MIME file and send it via
    email. When recipient decodes the file, UUDeview may execute arbitrary code
    which is embedded in the MIME file, thus granting the attacker access to
    the recipient\'s account.
  
Workaround

    There is no known workaround at this time. As a result, a software upgrade
    is required and users should upgrade to uudeview 0.5.20.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to uudeview 0.5.20:
    # emerge sync
    # emerge -pv ">=app-text/uudeview-0.5.20"
    # emerge ">=app-text/uudeview-0.5.20"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=76&type=vulnerabilities');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/bid/9758');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200403-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200403-05] UUDeview MIME Buffer Overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'UUDeview MIME Buffer Overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/uudeview", unaffected: make_list("ge 0.5.20"), vulnerable: make_list("lt 0.5.20")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

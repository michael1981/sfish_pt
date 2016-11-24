# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-17.xml
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
 script_id(20079);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200510-17");
 script_cve_id("CVE-2005-2972");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-17
(AbiWord: New RTF import buffer overflows)


    Chris Evans discovered a different set of buffer overflows than
    the one described in GLSA 200509-20 in the RTF import function in
    AbiWord.
  
Impact

    An attacker could design a malicious RTF file and entice a user to
    import it in AbiWord, potentially resulting in the execution of
    arbitrary code with the rights of the user running AbiWord.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All AbiWord users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/abiword-2.2.11"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200509-20.xml');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2972');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-17] AbiWord: New RTF import buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AbiWord: New RTF import buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-office/abiword", unaffected: make_list("ge 2.2.11"), vulnerable: make_list("lt 2.2.11")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

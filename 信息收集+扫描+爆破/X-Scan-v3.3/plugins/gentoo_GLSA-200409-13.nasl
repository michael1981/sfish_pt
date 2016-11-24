# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-13.xml
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
 script_id(14694);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200409-13");
 script_cve_id("CVE-2004-0694", "CVE-2004-0745", "CVE-2004-0769", "CVE-2004-0771");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-13
(LHa: Multiple vulnerabilities)


    The command line argument as well as the archive parsing code of LHa lack
    sufficient bounds checking. Furthermore, a shell meta character command
    execution vulnerability exists in LHa, since it does no proper filtering on
    directory names.
  
Impact

    Using a specially crafted command line argument or archive, an attacker can
    cause a buffer overflow and could possibly run arbitrary code. The shell
    meta character command execution could lead to the execution of arbitrary
    commands by an attacker using directories containing shell meta characters
    in their names.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All LHa users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=app-arch/lha-114i-r4"
    # emerge ">=app-arch/lha-114i-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0694');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0745');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0769');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0771');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-13] LHa: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LHa: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/lha", unaffected: make_list("rge 114i-r4"), vulnerable: make_list("rle 114i-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

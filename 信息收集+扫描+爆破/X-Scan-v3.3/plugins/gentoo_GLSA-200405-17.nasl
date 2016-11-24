# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-17.xml
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
 script_id(14503);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200405-17");
 script_cve_id("CVE-2004-0104", "CVE-2004-0105");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-17
(Multiple vulnerabilities in metamail)


    Ulf Harnhammar found two format string bugs and two buffer overflow bugs in
    Metamail.
  
Impact

    A remote attacker could send a malicious email message and execute
    arbitrary code with the rights of the process calling the Metamail program.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All users of Metamail should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-mail/metamail-2.7.45.3"
    # emerge ">=net-mail/metamail-2.7.45.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0104');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0105');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-17] Multiple vulnerabilities in metamail');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple vulnerabilities in metamail');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/metamail", unaffected: make_list("ge 2.7.45.3"), vulnerable: make_list("lt 2.7.45.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

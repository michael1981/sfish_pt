# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200612-12.xml
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
 script_id(23864);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200612-12");
 script_cve_id("CVE-2006-6293", "CVE-2006-6294", "CVE-2006-6352");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200612-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200612-12
(F-PROT Antivirus: Multiple vulnerabilities)


    F-Prot Antivirus version 4.6.7 fixes a heap-based buffer overflow, an
    infinite loop, and other unspecified vulnerabilities.
  
Impact

    Among other weaker impacts, a remote attacker could send an e-mail
    containing a malicious file that would trigger the buffer overflow
    vulnerability and execute arbitrary code with the privileges of the
    user running F-Prot, which may be the root user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All F-Prot users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/f-prot-4.6.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6293');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6294');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6352');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200612-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200612-12] F-PROT Antivirus: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'F-PROT Antivirus: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/f-prot", unaffected: make_list("ge 4.6.7"), vulnerable: make_list("lt 4.6.7")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

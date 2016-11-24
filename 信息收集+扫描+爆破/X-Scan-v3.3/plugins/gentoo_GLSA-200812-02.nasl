# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-02.xml
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
 script_id(35019);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200812-02");
 script_cve_id("CVE-2008-3863", "CVE-2008-4306");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-02
(enscript: User-assisted execution of arbitrary code)


    Two stack-based buffer overflows in the read_special_escape() function
    in src/psgen.c have been reported. Ulf Harnhammar of Secunia Research
    discovered a vulnerability related to the "setfilename" command
    (CVE-2008-3863), and Kees Cook of Ubuntu discovered a vulnerability
    related to the "font" escape sequence (CVE-2008-4306).
  
Impact

    An attacker could entice a user or automated system to process
    specially crafted input with the special escapes processing enabled
    using the "-e" option, possibly resulting in the execution of arbitrary
    code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All enscript users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/enscript-1.6.4-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3863');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4306');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-02] enscript: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'enscript: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/enscript", unaffected: make_list("ge 1.6.4-r4"), vulnerable: make_list("lt 1.6.4-r4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

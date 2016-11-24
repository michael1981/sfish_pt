# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200905-02.xml
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
 script_id(38883);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200905-02");
 script_cve_id("CVE-2009-0148", "CVE-2009-1577");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200905-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200905-02
(Cscope: User-assisted execution of arbitrary code)


    James Peach of Apple discovered a stack-based buffer overflow in
    cscope\'s handling of long file system paths (CVE-2009-0148). Multiple
    stack-based buffer overflows were reported in the putstring function
    when processing an overly long function name or symbol in a source code
    file (CVE-2009-1577).
  
Impact

    A remote attacker could entice a user to open a specially crafted
    source file, possibly resulting in the remote execution of arbitrary
    code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Cscope users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/cscope-15.7a"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0148');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1577');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200905-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200905-02] Cscope: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cscope: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/cscope", unaffected: make_list("ge 15.7a"), vulnerable: make_list("lt 15.7a")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200901-02.xml
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
 script_id(35346);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200901-02");
 script_cve_id("CVE-2008-4575", "CVE-2008-4639", "CVE-2008-4640", "CVE-2008-4641");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200901-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200901-02
(JHead: Multiple vulnerabilities)


    Marc Merlin and John Dong reported multiple vulnerabilities in JHead:
    A buffer overflow in the DoCommand() function when processing the cmd
    argument and related to potential string overflows (CVE-2008-4575).
    An insecure creation of a temporary file (CVE-2008-4639).
    A error when unlinking a file (CVE-2008-4640).
    Insufficient escaping of shell metacharacters (CVE-2008-4641).
  
Impact

    A remote attacker could possibly execute arbitrary code by enticing a
    user or automated system to open a file with a long filename or via
    unspecified vectors. It is also possible to trick a user into deleting
    or overwriting files.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All JHead users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/jhead-2.84-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4575');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4639');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4640');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4641');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200901-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200901-02] JHead: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'JHead: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/jhead", unaffected: make_list("ge 2.84-r1"), vulnerable: make_list("lt 2.84-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

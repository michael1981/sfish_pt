# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-07.xml
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
 script_id(14518);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200406-07");
 script_cve_id("CVE-2004-0413");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-07
(Subversion: Remote heap overflow)


    The svn protocol parser trusts the indicated length of a URI string sent by
    a client. This allows a client to specify a very long string, thereby
    causing svnserve to allocate enough memory to hold that string. This may
    cause a Denial of Service. Alternately, given a string that causes an
    integer overflow in the variable holding the string length, the server
    might allocate less memory than required, allowing a heap overflow. This
    heap overflow may then be exploitable, allowing remote code execution. The
    attacker does not need read or write access to the Subversion repository
    being served, since even un-authenticated users can send svn protocol
    requests.
  
Impact

    Ranges from remote Denial of Service to potential arbitrary code execution
    with privileges of the svnserve process.
  
Workaround

    Servers without svnserve running are not vulnerable. Disable svnserve and
    use DAV for access instead.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the latest version of Subversion.
    # emerge sync
    # emerge -pv ">=dev-util/subversion-1.0.4-r1"
    # emerge ">=dev-util/subversion-1.0.4-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0413');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-07] Subversion: Remote heap overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Subversion: Remote heap overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/subversion", unaffected: make_list("ge 1.0.4-r1"), vulnerable: make_list("le 1.0.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

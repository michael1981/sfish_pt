# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-29.xml
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
 script_id(15581);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200410-29");
 script_cve_id("CVE-2004-1008");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-29 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-29
(PuTTY: Pre-authentication buffer overflow)


    PuTTY fails to do proper bounds checking on SSH2_MSG_DEBUG packets. The
    "stringlen" parameter value is incorrectly checked due to signedness
    issues. Note that this vulnerability is similar to the one described in
    GLSA 200408-04 but not the same.
  
Impact

    When PuTTY connects to a server using the SSH2 protocol, an attacker
    may be able to send specially crafted packets to the client, resulting
    in the execution of arbitrary code with the permissions of the user
    running PuTTY. Note that this is possible during the authentication
    process but before host key verification.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PuTTY users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/putty-0.56"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=155');
script_set_attribute(attribute: 'see_also', value: 'http://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1008');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-29.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-29] PuTTY: Pre-authentication buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PuTTY: Pre-authentication buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/putty", unaffected: make_list("ge 0.56"), vulnerable: make_list("le 0.55")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

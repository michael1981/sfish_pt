# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-28.xml
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
 script_id(17164);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200502-28");
 script_cve_id("CVE-2005-0467");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-28 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-28
(PuTTY: Remote code execution)


    Two vulnerabilities have been discovered in the PSCP and PSFTP
    clients, which can be triggered by the SFTP server itself. These issues
    are caused by the improper handling of the FXP_READDIR response, along
    with other string fields.
  
Impact

    An attacker can setup a malicious SFTP server that would send
    these malformed responses to a client, potentially allowing the
    execution of arbitrary code on their system.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PuTTY users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/putty-0.57"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-sftp-readdir.html');
script_set_attribute(attribute: 'see_also', value: 'http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-sftp-string.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0467');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=201&type=vulnerabilities');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-28.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-28] PuTTY: Remote code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PuTTY: Remote code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/putty", unaffected: make_list("ge 0.57"), vulnerable: make_list("lt 0.57")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

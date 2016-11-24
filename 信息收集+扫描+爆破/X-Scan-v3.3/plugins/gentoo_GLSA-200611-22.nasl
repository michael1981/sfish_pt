# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-22.xml
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
 script_id(23730);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200611-22");
 script_cve_id("CVE-2006-5449");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-22
(Ingo H3: Folder name shell command injection)


    Ingo H3 fails to properly escape shell metacharacters in procmail
    rules.
  
Impact

    A remote authenticated attacker could craft a malicious rule which
    could lead to the execution of arbitrary shell commands on the server.
  
Workaround

    Don\'t use procmail with Ingo H3.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ingo H3 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-ingo-1.1.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5449');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-22] Ingo H3: Folder name shell command injection');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ingo H3: Folder name shell command injection');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/horde-ingo", unaffected: make_list("ge 1.1.2"), vulnerable: make_list("lt 1.1.2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-04.xml
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
 script_id(16395);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200501-04");
 script_cve_id("CVE-2004-1373");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-04
(Shoutcast Server: Remote code execution)


    Part of the Shoutcast Server Linux binary has been found to improperly
    handle sprintf() parsing.
  
Impact

    A malicious attacker could send a formatted URL request to the
    Shoutcast Server. This formatted URL would cause either the server
    process to crash, or the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Shoutcast Server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/shoutcast-server-bin-1.9.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/385350');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1373');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-04] Shoutcast Server: Remote code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Shoutcast Server: Remote code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/shoutcast-server-bin", unaffected: make_list("ge 1.9.5"), vulnerable: make_list("le 1.9.4-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

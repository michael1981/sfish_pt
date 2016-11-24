# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200610-10.xml
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
 script_id(22913);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200610-10");
 script_cve_id("CVE-2006-4182");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200610-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200610-10
(ClamAV: Multiple Vulnerabilities)


    Damian Put and an anonymous researcher reported a potential heap-based
    buffer overflow vulnerability in rebuildpe.c responsible for the
    rebuilding of an unpacked PE file, and a possible crash in chmunpack.c
    in the CHM unpacker.
  
Impact

    By sending a malicious attachment to a mail server running ClamAV, or
    providing a malicious file to ClamAV through any other method, a remote
    attacker could cause a Denial of Service and potentially the execution
    of arbitrary code with the permissions of the user running ClamAV.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.88.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://sourceforge.net/project/shownotes.php?release_id=455799');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4182');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200610-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200610-10] ClamAV: Multiple Vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Multiple Vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.88.5"), vulnerable: make_list("lt 0.88.5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

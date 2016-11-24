# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-13.xml
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
 script_id(22199);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200608-13");
 script_cve_id("CVE-2006-4018");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200608-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200608-13
(ClamAV: Heap buffer overflow)


    Damian Put has discovered a boundary error in the pefromupx() function
    used by the UPX extraction module, which unpacks PE Windows executable
    files. Both the "clamscan" command-line utility and the "clamd" daemon
    are affected.
  
Impact

    By sending a malicious attachment to a mail server running ClamAV, a
    remote attacker can cause a Denial of Service and potentially the
    execution of arbitrary code with the permissions of the user running
    ClamAV.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.88.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.clamav.net/security/0.88.4.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4018');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200608-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200608-13] ClamAV: Heap buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Heap buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.88.4"), vulnerable: make_list("lt 0.88.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

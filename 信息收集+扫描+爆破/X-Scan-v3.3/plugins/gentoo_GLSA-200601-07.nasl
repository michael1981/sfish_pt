# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-07.xml
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
 script_id(20417);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200601-07");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200601-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200601-07
(ClamAV: Remote execution of arbitrary code)


    Zero Day Initiative (ZDI) reported a heap buffer overflow
    vulnerability. The vulnerability is due to an incorrect boundary check
    of the user-supplied data prior to copying it to an insufficiently
    sized memory buffer. The flaw occurs when the application attempts to
    handle compressed UPX files.
  
Impact

    For example by sending a maliciously crafted UPX file into a mail
    server that is integrated with ClamAV, a remote attacker\'s supplied
    code could be executed with escalated privileges.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.88"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0162');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200601-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200601-07] ClamAV: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.88"), vulnerable: make_list("lt 0.88")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

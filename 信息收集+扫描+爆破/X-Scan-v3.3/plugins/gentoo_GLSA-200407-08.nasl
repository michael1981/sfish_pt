# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-08.xml
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
 script_id(14541);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200407-08");
 script_cve_id("CVE-2004-0633", "CVE-2004-0634", "CVE-2004-0635");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-08
(Ethereal: Multiple security problems)


    There are multiple vulnerabilities in versions of Ethereal earlier than
    0.10.5, including:
    In some cases the iSNS dissector could cause Ethereal to
    abort.
    If there was no policy name for a handle for SMB SID snooping it
    could cause a crash.
    A malformed or missing community string could cause the SNMP
    dissector to crash.
  
Impact

    An attacker could use these vulnerabilities to crash Ethereal or even
    execute arbitrary code with the permissions of the user running
    Ethereal, which could be the root user.
  
Workaround

    For a temporary workaround you can disable all affected protocol
    dissectors by selecting Analyze->Enabled Protocols... and deselecting
    them from the list. For SMB you can disable SID snooping in the SMB
    protocol preference. However, it is strongly recommended to upgrade to
    the latest stable version.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ethereal users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-analyzer/ethereal-0.10.5"
    # emerge ">=net-analyzer/ethereal-0.10.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.ethereal.com/appnotes/enpa-sa-00015.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0633');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0634');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0635');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-08] Ethereal: Multiple security problems');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Multiple security problems');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.5"), vulnerable: make_list("le 0.10.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

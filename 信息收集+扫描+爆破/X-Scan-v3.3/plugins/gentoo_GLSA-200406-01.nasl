# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-01.xml
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
 script_id(14512);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200406-01");
 script_cve_id("CVE-2004-0504", "CVE-2004-0505", "CVE-2004-0506", "CVE-2004-0507");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-01
(Ethereal: Multiple security problems)


    There are multiple vulnerabilities in versions of Ethereal earlier than
    0.10.4, including:
    A buffer overflow in the MMSE dissector.
    Under specific conditions a SIP packet could make Ethereal
    crash.
    The AIM dissector could throw an assertion, causing Ethereal to
    crash.
    The SPNEGO dissector could dereference a null pointer, causing a
    crash.
  
Impact

    An attacker could use these vulnerabilities to crash Ethereal or even
    execute arbitrary code with the permissions of the user running
    Ethereal, which could be the root user.
  
Workaround

    For a temporary workaround you can disable all affected protocol
    dissectors by selecting Analyze->Enabled Protocols... and deselecting
    them from the list. However, it is strongly recommended to upgrade to
    the latest stable release.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ethereal users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-analyzer/ethereal-0.10.4"
    # emerge ">=net-analyzer/ethereal-0.10.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.ethereal.com/appnotes/enpa-sa-00014.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0504');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0505');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0506');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0507');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-01] Ethereal: Multiple security problems');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Multiple security problems');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.4"), vulnerable: make_list("le 0.10.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

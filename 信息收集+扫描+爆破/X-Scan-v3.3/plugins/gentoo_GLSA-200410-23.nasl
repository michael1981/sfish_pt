# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-23.xml
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
 script_id(15559);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200410-23");
 script_cve_id("CVE-2004-0891");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-23
(Gaim: Multiple vulnerabilities)


    A possible buffer overflow exists in the code processing MSN SLP messages
    (CAN-2004-0891). memcpy() was used without validating the size of the
    buffer, and an incorrect buffer was used as destination under certain
    circumstances. Additionally, memory allocation problems were found in the
    processing of MSN SLP messages and the receiving of files. These issues
    could lead Gaim to try to allocate more memory than available, resulting in
    the crash of the application.
  
Impact

    A remote attacker could crash Gaim and possibly execute arbitrary code by
    exploiting the buffer overflow.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Gaim users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-im/gaim-1.0.2"
    # emerge ">=net-im/gaim-1.0.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0891');
script_set_attribute(attribute: 'see_also', value: 'http://gaim.sourceforge.net/security/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-23] Gaim: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 1.0.2"), vulnerable: make_list("lt 1.0.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

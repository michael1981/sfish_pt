# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200806-04.xml
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
 script_id(33189);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200806-04");
 script_cve_id("CVE-2008-1801", "CVE-2008-1802", "CVE-2008-1803");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200806-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200806-04
(rdesktop: Multiple vulnerabilities)


    An anonymous researcher reported multiple vulnerabilities in rdesktop
    via iDefense Labs:
    An integer underflow error exists in
    the function iso_recv_msg() in the file iso.c which can be triggered
    via a specially crafted RDP request, causing a heap-based buffer
    overflow (CVE-2008-1801).
    An input validation error exists in
    the function process_redirect_pdu() in the file rdp.c which can be
    triggered via a specially crafted RDP redirect request, causing a
    BSS-based buffer overflow (CVE-2008-1802).
    An integer signedness error exists in the function xrealloc() in the
    file rdesktop.c which can be be exploited to cause a heap-based buffer
    overflow (CVE-2008-1803).
  
Impact

    An attacker could exploit these vulnerabilities by enticing a user to
    connect to a malicious RDP server thereby allowing the attacker to
    execute arbitrary code or cause a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All rdesktop users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/rdesktop-1.6.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1801');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1802');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1803');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200806-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200806-04] rdesktop: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rdesktop: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/rdesktop", unaffected: make_list("ge 1.6.0"), vulnerable: make_list("lt 1.6.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

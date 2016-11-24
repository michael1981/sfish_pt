# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200708-03.xml
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
 script_id(25868);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200708-03");
 script_cve_id("CVE-2007-3641", "CVE-2007-3644", "CVE-2007-3645");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200708-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200708-03
(libarchive (formerly named as bsdtar): Multiple PaX Extension Header Vulnerabilities)


    CPNI, CERT-FI, Tim Kientzle, and Colin Percival reported a buffer
    overflow (CVE-2007-3641), an infinite loop (CVE-2007-3644), and a NULL
    pointer dereference (CVE-2007-3645) within the processing of archives
    having corrupted PaX extension headers.
  
Impact

    An attacker can trick a user or automated system to process an archive
    with malformed PaX extension headers into execute arbitrary code, crash
    an application using the library, or cause a high CPU load.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libarchive or bsdtar users should upgrade to the latest libarchive
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/libarchive-2.2.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3641');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3644');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3645');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200708-03] libarchive (formerly named as bsdtar): Multiple PaX Extension Header Vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libarchive (formerly named as bsdtar): Multiple PaX Extension Header Vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/libarchive", unaffected: make_list("ge 2.2.4"), vulnerable: make_list("lt 2.2.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

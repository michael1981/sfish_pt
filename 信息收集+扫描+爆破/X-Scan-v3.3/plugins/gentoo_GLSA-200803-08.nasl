# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-08.xml
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
 script_id(31383);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200803-08");
 script_cve_id("CVE-2006-4382", "CVE-2006-4384", "CVE-2006-4385", "CVE-2006-4386", "CVE-2006-4388", "CVE-2006-4389", "CVE-2007-4674", "CVE-2007-6166");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-08
(Win32 binary codecs: Multiple vulnerabilities)


    Multiple buffer overflow, heap overflow, and integer overflow
    vulnerabilities were discovered in the Quicktime plugin when processing
    MOV, FLC, SGI, H.264 and FPX files.
  
Impact

    A remote attacker could entice a user to open a specially crafted video
    file, possibly resulting in the remote execution of arbitrary code with
    the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Win32 binary codecs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/win32codecs-20071007-r2"
    Note: Since no updated binary versions have been released, the
    Quicktime libraries have been removed from the package. Please use the
    free alternative Quicktime implementations within VLC, MPlayer or Xine
    for playback.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4382');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4384');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4385');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4386');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4388');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4389');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4674');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6166');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-08] Win32 binary codecs: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Win32 binary codecs: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/win32codecs", unaffected: make_list("ge 20071007-r2"), vulnerable: make_list("lt 20071007-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

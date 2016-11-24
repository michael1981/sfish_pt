# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-21.xml
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
 script_id(35819);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200903-21");
 script_cve_id("CVE-2009-0037");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-21
(cURL: Arbitrary file access)


    David Kierznowski reported that the redirect implementation accepts
    arbitrary Location values when CURLOPT_FOLLOWLOCATION is enabled.
  
Impact

    A remote attacker could possibly exploit this vulnerability to make
    remote HTTP servers trigger arbitrary requests to intranet servers and
    read or overwrite arbitrary files via a redirect to a file: URL, or, if
    the libssh2 USE flag is enabled, execute arbitrary commands via a
    redirect to an scp: URL.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All cURL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/curl-7.19.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0037');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-21] cURL: Arbitrary file access');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'cURL: Arbitrary file access');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/curl", unaffected: make_list("ge 7.19.4"), vulnerable: make_list("lt 7.19.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

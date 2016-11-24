# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-14.xml
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
 script_id(14500);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200405-14");
 script_cve_id("CVE-2004-0397");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-14
(Buffer overflow in Subversion)


    All releases of Subversion prior to 1.0.3 have a vulnerability in the
    date-parsing code. This vulnerability may allow denial of service or
    arbitrary code execution as the Subversion user. Both the client and
    server are vulnerable, and write access is NOT required to the server\'s
    repository.
  
Impact

    All servers and clients are vulnerable. Specifically, clients that
    allow other users to write to administrative files in a working copy
    may be exploited. Additionally all servers (whether they are httpd/DAV
    or svnserve) are vulnerable. Write access to the server is not
    required; public read-only Subversion servers are also exploitable.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
');
script_set_attribute(attribute:'solution', value: '
    All Subversion users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=dev-util/subversion-1.0.3"
    # emerge ">=dev-util/subversion-1.0.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://subversion.tigris.org/servlets/ReadMsg?list=announce&msgNo=125');
script_set_attribute(attribute: 'see_also', value: 'http://security.e-matters.de/advisories/082004.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0397');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-14] Buffer overflow in Subversion');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Buffer overflow in Subversion');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/subversion", unaffected: make_list("ge 1.0.3"), vulnerable: make_list("le 1.0.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200612-21.xml
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
 script_id(23958);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200612-21");
 script_cve_id("CVE-2006-6303");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200612-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200612-21
(Ruby: Denial of Service vulnerability)


    The read_multipart function of the CGI library shipped with Ruby
    (cgi.rb) does not properly check boundaries in MIME multipart content.
    This is a different issue than GLSA 200611-12.
  
Impact

    The vulnerability can be exploited by sending the cgi.rb library a
    crafted HTTP request with multipart MIME encoding that contains a
    malformed MIME boundary specifier. Successful exploitation of the
    vulnerability causes the library to go into an infinite loop.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ruby users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/ruby-1.8.5_p2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6303');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200612-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200612-21] Ruby: Denial of Service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ruby: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/ruby", unaffected: make_list("ge 1.8.5_p2"), vulnerable: make_list("lt 1.8.5_p2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

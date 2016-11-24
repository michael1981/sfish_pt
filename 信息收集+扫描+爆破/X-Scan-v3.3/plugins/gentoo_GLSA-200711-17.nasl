# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-17.xml
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
 script_id(28217);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200711-17");
 script_cve_id("CVE-2007-3227", "CVE-2007-5379", "CVE-2007-5380");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-17
(Ruby on Rails: Multiple vulnerabilities)


    candlerb found that ActiveResource, when processing responses using the
    Hash.from_xml() function, does not properly sanitize filenames
    (CVE-2007-5380). The session management functionality allowed the
    "session_id" to be set in the URL (CVE-2007-5380). BCC discovered that
    the to_json() function does not properly sanitize input before
    returning it to the user (CVE-2007-3227).
  
Impact

    Unauthenticated remote attackers could exploit these vulnerabilities to
    determine the existence of files or to read the contents of arbitrary
    XML files; conduct session fixation attacks and gain unauthorized
    access; and to execute arbitrary HTML and script code in a user\'s
    browser session in context of an affected site by enticing a user to
    browse a specially crafted URL.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ruby on Rails users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-ruby/rails-1.2.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3227');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5379');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5380');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-17] Ruby on Rails: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ruby on Rails: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-ruby/rails", unaffected: make_list("ge 1.2.5"), vulnerable: make_list("lt 1.2.5")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

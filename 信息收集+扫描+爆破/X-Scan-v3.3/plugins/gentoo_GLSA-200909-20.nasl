# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-20.xml
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
 script_id(41637);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200909-20");
 script_cve_id("CVE-2009-2417");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-20
(cURL: Certificate validation error)


    Scott Cantor reported that cURL does not properly handle fields in
    X.509 certificates that contain an ASCII NUL (\\0) character.
    Specifically, the processing of such fields is stopped at the first
    occurence of a NUL character. This type of vulnerability was recently
    discovered by Dan Kaminsky and Moxie Marlinspike.
  
Impact

    A remote attacker might employ a specially crafted X.509 certificate
    (that for instance contains a NUL character in the Common Name field)
    to conduct man-in-the-middle attacks.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All cURL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =net-misc/curl-7.19.6
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2417');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-20] cURL: Certificate validation error');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'cURL: Certificate validation error');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/curl", unaffected: make_list("ge 7.19.6"), vulnerable: make_list("lt 7.19.6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

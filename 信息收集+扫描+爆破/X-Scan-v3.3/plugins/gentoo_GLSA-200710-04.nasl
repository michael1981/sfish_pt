# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-04.xml
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
 script_id(26944);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200710-04");
 script_cve_id("CVE-2007-4974");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-04
(libsndfile: Buffer overflow)


    Robert Buchholz of the Gentoo Security team discovered that the
    flac_buffer_copy() function does not correctly handle FLAC streams with
    variable block sizes which leads to a heap-based buffer overflow
    (CVE-2007-4974).
  
Impact

    A remote attacker could exploit this vulnerability by enticing a user
    to open a specially crafted FLAC file or network stream with an
    application using libsndfile. This might lead to the execution of
    arbitrary code with privileges of the user playing the file.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libsndfile users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libsndfile-1.0.17-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4974');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-04] libsndfile: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libsndfile: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libsndfile", unaffected: make_list("ge 1.0.17-r1"), vulnerable: make_list("lt 1.0.17-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

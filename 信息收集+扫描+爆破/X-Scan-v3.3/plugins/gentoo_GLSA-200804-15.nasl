# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-15.xml
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
 script_id(31962);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200804-15");
 script_cve_id("CVE-2008-1382");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-15
(libpng: Execution of arbitrary code)


    Tavis Ormandy of the Google Security Team discovered that libpng does
    not handle zero-length unknown chunks in PNG files correctly, which
    might lead to memory corruption in applications that call
    png_set_read_user_chunk_fn() or png_set_keep_unknown_chunks().
  
Impact

    A remote attacker could entice a user or automated system to process a
    specially crafted PNG image in an application using libpng and possibly
    execute arbitrary code with the privileges of the user running the
    application. Note that processing of unknown chunks is disabled by
    default in most PNG applications, but some such as ImageMagick are
    affected.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libpng users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libpng-1.2.26-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1382');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-15] libpng: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libpng: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libpng", unaffected: make_list("ge 1.2.26-r1"), vulnerable: make_list("lt 1.2.26-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-14.xml
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
 script_id(21578);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200605-14");
 script_cve_id("CVE-2006-2458");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200605-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200605-14
(libextractor: Two heap-based buffer overflows)


    Luigi Auriemma has found two heap-based buffer overflows in
    libextractor 0.5.13 and earlier: one of them occurs in the
    asf_read_header function in the ASF plugin, and the other occurs in the
    parse_trak_atom function in the Qt plugin.
  
Impact

    By enticing a user to open a malformed file using an application
    that employs libextractor and its ASF or Qt plugins, an attacker could
    execute arbitrary code in the context of the application running the
    affected library.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libextractor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libextractor-0.5.14"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2458');
script_set_attribute(attribute: 'see_also', value: 'http://aluigi.altervista.org/adv/libextho-adv.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200605-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200605-14] libextractor: Two heap-based buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libextractor: Two heap-based buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libextractor", unaffected: make_list("ge 0.5.14"), vulnerable: make_list("lt 0.5.14")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200906-01.xml
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
 script_id(39561);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200906-01");
 script_cve_id("CVE-2009-2042");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200906-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200906-01
(libpng: Information disclosure)


    Jeff Phillips discovered that libpng does not properly parse 1-bit
    interlaced images with width values that are not divisible by 8, which
    causes libpng to include uninitialized bits in certain rows of a PNG
    file.
  
Impact

    A remote attacker might entice a user to open a specially crafted PNG
    file, possibly resulting in the disclosure of sensitive memory
    portions.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libpng users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libpng-1.2.37"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2042');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200906-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200906-01] libpng: Information disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libpng: Information disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libpng", unaffected: make_list("ge 1.2.37"), vulnerable: make_list("lt 1.2.37")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

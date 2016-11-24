# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-09.xml
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
 script_id(17275);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200503-09");
 script_cve_id("CVE-2005-0665");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-09
(xv: Filename handling vulnerability)


    Tavis Ormandy of the Gentoo Linux Security Audit Team identified a flaw
    in the handling of image filenames by xv.
  
Impact

    Successful exploitation would require a victim to process a specially
    crafted image with a malformed filename, potentially resulting in the
    execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All xv users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/xv-3.10a-r10"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0665');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-09] xv: Filename handling vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xv: Filename handling vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/xv", unaffected: make_list("ge 3.10a-r10"), vulnerable: make_list("lt 3.10a-r10")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

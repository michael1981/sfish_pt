# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-08.xml
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
 script_id(26098);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200709-08");
 script_cve_id("CVE-2007-4460");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-08
(id3lib: Insecure temporary file creation)


    Nikolaus Schulz discovered that the function RenderV2ToFile() in file
    src/tag_file.cpp creates temporary files in an insecure manner.
  
Impact

    A local attacker could exploit this vulnerability via a symlink attack
    to overwrite arbitrary files.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All id3lib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/id3lib-3.8.3-r6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4460');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-08] id3lib: Insecure temporary file creation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'id3lib: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/id3lib", unaffected: make_list("ge 3.8.3-r6"), vulnerable: make_list("lt 3.8.3-r6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
